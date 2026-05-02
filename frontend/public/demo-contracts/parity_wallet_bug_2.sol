pragma solidity ^0.4.18;

contract WalletLibrary {
    address[] public owners;
    uint public required;
    bool public initialized;

    modifier only_uninitialized {
        require(!initialized);
        _;
    }

    function initWallet(address[] _owners, uint _required) public only_uninitialized {
        owners = _owners;
        required = _required;
        initialized = true;
    }

    function kill(address _to) public {
        selfdestruct(_to);
    }
}
