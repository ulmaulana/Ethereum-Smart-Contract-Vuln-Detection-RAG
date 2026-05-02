pragma solidity ^0.4.24;

contract BECToken {
    mapping(address => uint256) public balanceOf;

    function batchTransfer(address[] _receivers, uint256 _value) public {
        uint256 cnt = _receivers.length;
        uint256 amount = cnt * _value;
        require(cnt > 0 && cnt <= 20);
        require(_value > 0 && balanceOf[msg.sender] >= amount);

        balanceOf[msg.sender] -= amount;
        for (uint256 i = 0; i < cnt; i++) {
            balanceOf[_receivers[i]] += _value;
        }
    }
}
