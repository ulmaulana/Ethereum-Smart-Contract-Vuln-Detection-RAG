from __future__ import annotations

from pathlib import Path

from case_study.hack_metadata import HACK_CONTRACTS


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CURATED_ROOT = PROJECT_ROOT / "dataset" / "smartbugs-curated-main" / "dataset"


INLINE_REGRESSION_CASES = [
    {
        "id": "custom_vulnerable_bank",
        "name": "Custom VulnerableBank",
        "type": "inline",
        "filename": "VulnerableBank.sol",
        "expected_classes": ["reentrancy", "access_control", "arithmetic"],
        "source_code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function emergencyWithdraw() public {
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }

    function unsafeAddBalance(address user, uint256 amount) public {
        balances[user] += amount;
    }

    function changeOwner(address newOwner) public {
        owner = newOwner;
    }

    function destroy() public {
        selfdestruct(payable(msg.sender));
    }

    receive() external payable {}
}
""",
    },
    {
        "id": "custom_safe_vault",
        "name": "Custom SafeVault",
        "type": "inline",
        "filename": "SafeVault.sol",
        "expected_classes": [],
        "source_code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SafeVault {
    mapping(address => uint256) public balances;
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
    }

    function rescue(address payable recipient, uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "insufficient balance");
        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "rescue failed");
    }
}
""",
    },
    {
        "id": "custom_time_randomness",
        "name": "Custom TimeRandomness",
        "type": "inline",
        "filename": "TimeRandomness.sol",
        "expected_classes": ["bad_randomness", "time_manipulation"],
        "source_code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract TimeRandomness {
    function draw() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1)))) % 10;
    }
}
""",
    },
]


def build_regression_cases() -> list[dict]:
    cases = []
    for hack in HACK_CONTRACTS:
        source_path = CURATED_ROOT / hack["category_folder"] / hack["filename"]
        cases.append(
            {
                "id": hack["id"],
                "name": hack["name"],
                "type": "curated",
                "filename": hack["filename"],
                "expected_classes": list(hack["expected_classes"]),
                "source_path": str(source_path),
            }
        )
    cases.extend(INLINE_REGRESSION_CASES)
    return cases
