// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title SplitTheBill
 * @dev A group payment escrow system using PYUSD for bill splitting
 * @notice This contract allows groups to collect payments before sending to merchant
 */
contract SplitTheBill is ReentrancyGuard, Pausable, Ownable, EIP712 {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    // PYUSD contract addresses
    address public constant PYUSD_ETHEREUM = 0x6c3ea9036406852006290770BEdFcAbA0e23A0e8;
    address public constant PYUSD_ARBITRUM = 0x46850aD61C2B7d64d08c9C754F45254596696984;
    
    // Events
    event BillCreated(
        bytes32 indexed billId,
        address indexed creator,
        address indexed merchant,
        uint256 totalAmount,
        uint256 deadline,
        string metadata
    );
    
    event ContributionAdded(
        bytes32 indexed billId,
        address indexed contributor,
        uint256 amount,
        uint256 totalCollected
    );
    
    event BillPaid(
        bytes32 indexed billId,
        address indexed merchant,
        uint256 totalAmount,
        uint256 timestamp
    );
    
    event BillRefunded(
        bytes32 indexed billId,
        uint256 totalRefunded
    );

    event ContributorRemoved(
        bytes32 indexed billId,
        address indexed contributor,
        uint256 refundAmount
    );

    // Structs
    struct Bill {
        bytes32 billId;
        address creator;
        address merchant;
        address pyusdContract;
        uint256 totalAmount;
        uint256 collectedAmount;
        uint256 deadline;
        uint256 createdAt;
        bool isPaid;
        bool isRefunded;
        string metadata; // JSON metadata for bill details
        mapping(address => uint256) contributions;
        address[] contributors;
    }

    struct GroupSignature {
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 nonce;
        uint256 deadline;
    }

    // State variables
    mapping(bytes32 => Bill) public bills;
    mapping(address => uint256) public nonces;
    bytes32 private constant CONTRIBUTION_TYPEHASH = 
        keccak256("Contribution(address contributor,bytes32 billId,uint256 amount,uint256 nonce,uint256 deadline)");
    
    uint256 public serviceFeePercentage = 50; // 0.5% (50/10000)
    address public feeCollector;
    
    modifier validBill(bytes32 billId) {
        require(bills[billId].creator != address(0), "Bill does not exist");
        _;
    }
    
    modifier notPaid(bytes32 billId) {
        require(!bills[billId].isPaid, "Bill already paid");
        _;
    }
    
    modifier notExpired(bytes32 billId) {
        require(block.timestamp <= bills[billId].deadline, "Bill expired");
        _;
    }

    constructor(address _feeCollector) EIP712("SplitTheBill", "1") {
        feeCollector = _feeCollector;
    }

    /**
     * @dev Create a new bill for group payment
     * @param merchant Address to receive payment
     * @param totalAmount Total amount required in PYUSD
     * @param deadline Unix timestamp for payment deadline
     * @param metadata JSON string with bill details
     * @param pyusdContract PYUSD contract address (chain-specific)
     */
    function createBill(
        address merchant,
        uint256 totalAmount,
        uint256 deadline,
        string calldata metadata,
        address pyusdContract
    ) external returns (bytes32 billId) {
        require(merchant != address(0), "Invalid merchant address");
        require(totalAmount > 0, "Amount must be greater than 0");
        require(deadline > block.timestamp, "Deadline must be in the future");
        require(
            pyusdContract == PYUSD_ETHEREUM || pyusdContract == PYUSD_ARBITRUM,
            "Invalid PYUSD contract"
        );

        billId = keccak256(
            abi.encodePacked(
                msg.sender,
                merchant,
                totalAmount,
                deadline,
                block.timestamp,
                block.number
            )
        );

        Bill storage newBill = bills[billId];
        newBill.billId = billId;
        newBill.creator = msg.sender;
        newBill.merchant = merchant;
        newBill.pyusdContract = pyusdContract;
        newBill.totalAmount = totalAmount;
        newBill.deadline = deadline;
        newBill.createdAt = block.timestamp;
        newBill.metadata = metadata;

        emit BillCreated(billId, msg.sender, merchant, totalAmount, deadline, metadata);
    }

    /**
     * @dev Contribute to a bill
     * @param billId The bill identifier
     * @param amount Amount to contribute in PYUSD
     */
    function contribute(bytes32 billId, uint256 amount) 
        external 
        validBill(billId) 
        notPaid(billId) 
        notExpired(billId) 
        nonReentrant 
    {
        require(amount > 0, "Amount must be greater than 0");
        
        Bill storage bill = bills[billId];
        require(
            bill.collectedAmount + amount <= bill.totalAmount,
            "Contribution exceeds required amount"
        );

        // Transfer PYUSD from contributor to contract
        IERC20(bill.pyusdContract).safeTransferFrom(msg.sender, address(this), amount);

        // Track contribution
        if (bill.contributions[msg.sender] == 0) {
            bill.contributors.push(msg.sender);
        }
        bill.contributions[msg.sender] += amount;
        bill.collectedAmount += amount;

        emit ContributionAdded(billId, msg.sender, amount, bill.collectedAmount);

        // Auto-pay if target reached
        if (bill.collectedAmount >= bill.totalAmount) {
            _payBill(billId);
        }
    }

    /**
     * @dev Contribute with authorization (gasless transaction)
     * @param billId The bill identifier
     * @param amount Amount to contribute
     * @param deadline Signature deadline
     * @param v,r,s Signature components
     */
    function contributeWithAuthorization(
        bytes32 billId,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external validBill(billId) notPaid(billId) notExpired(billId) {
        require(amount > 0, "Amount must be greater than 0");
        require(deadline >= block.timestamp, "Authorization expired");

        Bill storage bill = bills[billId];
        require(
            bill.collectedAmount + amount <= bill.totalAmount,
            "Contribution exceeds required amount"
        );

        // Verify signature for gasless transaction
        bytes32 structHash = keccak256(
            abi.encode(
                CONTRIBUTION_TYPEHASH,
                msg.sender,
                billId,
                amount,
                nonces[msg.sender]++,
                deadline
            )
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(v, r, s);
        require(signer == msg.sender, "Invalid signature");

        // Use PYUSD's transferWithAuthorization for gasless transfer
        // Note: This would require implementing the specific PYUSD interface
        // For now, we'll use regular transferFrom
        IERC20(bill.pyusdContract).safeTransferFrom(msg.sender, address(this), amount);

        // Track contribution
        if (bill.contributions[msg.sender] == 0) {
            bill.contributors.push(msg.sender);
        }
        bill.contributions[msg.sender] += amount;
        bill.collectedAmount += amount;

        emit ContributionAdded(billId, msg.sender, amount, bill.collectedAmount);

        // Auto-pay if target reached
        if (bill.collectedAmount >= bill.totalAmount) {
            _payBill(billId);
        }
    }

    /**
     * @dev Internal function to pay the merchant
     */
    function _payBill(bytes32 billId) internal {
        Bill storage bill = bills[billId];
        require(bill.collectedAmount >= bill.totalAmount, "Insufficient funds");
        
        bill.isPaid = true;
        
        // Calculate service fee
        uint256 serviceFee = (bill.totalAmount * serviceFeePercentage) / 10000;
        uint256 merchantAmount = bill.totalAmount - serviceFee;
        
        // Transfer to merchant and fee collector
        IERC20(bill.pyusdContract).safeTransfer(bill.merchant, merchantAmount);
        if (serviceFee > 0) {
            IERC20(bill.pyusdContract).safeTransfer(feeCollector, serviceFee);
        }

        emit BillPaid(billId, bill.merchant, bill.totalAmount, block.timestamp);
    }

    /**
     * @dev Manually pay bill (if auto-pay failed)
     */
    function payBill(bytes32 billId) 
        external 
        validBill(billId) 
        notPaid(billId) 
        nonReentrant 
    {
        Bill storage bill = bills[billId];
        require(bill.collectedAmount >= bill.totalAmount, "Insufficient funds collected");
        _payBill(billId);
    }

    /**
     * @dev Refund all contributors if bill expires or fails
     */
    function refundBill(bytes32 billId) 
        external 
        validBill(billId) 
        notPaid(billId) 
        nonReentrant 
    {
        Bill storage bill = bills[billId];
        require(
            block.timestamp > bill.deadline || msg.sender == bill.creator,
            "Cannot refund: bill not expired and not creator"
        );
        require(bill.collectedAmount > 0, "No funds to refund");
        
        bill.isRefunded = true;
        uint256 totalRefunded = 0;
        
        // Refund all contributors
        for (uint256 i = 0; i < bill.contributors.length; i++) {
            address contributor = bill.contributors[i];
            uint256 contribution = bill.contributions[contributor];
            if (contribution > 0) {
                bill.contributions[contributor] = 0;
                IERC20(bill.pyusdContract).safeTransfer(contributor, contribution);
                totalRefunded += contribution;
            }
        }
        
        bill.collectedAmount = 0;
        emit BillRefunded(billId, totalRefunded);
    }

    /**
     * @dev Remove a contributor and refund their contribution (creator only)
     */
    function removeContributor(bytes32 billId, address contributor) 
        external 
        validBill(billId) 
        notPaid(billId) 
        nonReentrant 
    {
        Bill storage bill = bills[billId];
        require(msg.sender == bill.creator, "Only creator can remove contributors");
        
        uint256 contribution = bill.contributions[contributor];
        require(contribution > 0, "Contributor has no contribution");
        
        bill.contributions[contributor] = 0;
        bill.collectedAmount -= contribution;
        
        IERC20(bill.pyusdContract).safeTransfer(contributor, contribution);
        
        emit ContributorRemoved(billId, contributor, contribution);
    }

    /**
     * @dev Calculate equal split amount
     */
    function calculateEqualSplit(bytes32 billId, uint256 numParticipants) 
        external 
        view 
        validBill(billId) 
        returns (uint256) 
    {
        require(numParticipants > 0, "Invalid number of participants");
        return bills[billId].totalAmount / numParticipants;
    }

    /**
     * @dev Get bill details
     */
    function getBillDetails(bytes32 billId) 
        external 
        view 
        validBill(billId) 
        returns (
            address creator,
            address merchant,
            uint256 totalAmount,
            uint256 collectedAmount,
            uint256 deadline,
            bool isPaid,
            bool isRefunded,
            string memory metadata
        ) 
    {
        Bill storage bill = bills[billId];
        return (
            bill.creator,
            bill.merchant,
            bill.totalAmount,
            bill.collectedAmount,
            bill.deadline,
            bill.isPaid,
            bill.isRefunded,
            bill.metadata
        );
    }

    /**
     * @dev Get contributor's contribution amount
     */
    function getContribution(bytes32 billId, address contributor) 
        external 
        view 
        validBill(billId) 
        returns (uint256) 
    {
        return bills[billId].contributions[contributor];
    }

    /**
     * @dev Get all contributors for a bill
     */
    function getContributors(bytes32 billId) 
        external 
        view 
        validBill(billId) 
        returns (address[] memory) 
    {
        return bills[billId].contributors;
    }

    /**
     * @dev Update service fee (owner only)
     */
    function updateServiceFee(uint256 newFeePercentage) external onlyOwner {
        require(newFeePercentage <= 500, "Fee cannot exceed 5%"); // Max 5%
        serviceFeePercentage = newFeePercentage;
    }

    /**
     * @dev Update fee collector (owner only)
     */
    function updateFeeCollector(address newFeeCollector) external onlyOwner {
        require(newFeeCollector != address(0), "Invalid address");
        feeCollector = newFeeCollector;
    }

    /**
     * @dev Pause contract (owner only)
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Unpause contract (owner only)
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @dev Emergency withdraw function (owner only)
     */
    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        IERC20(token).safeTransfer(owner(), amount);
    }
}
