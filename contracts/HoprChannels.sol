pragma solidity ^0.6.0;

// SPDX-License-Identifier: LGPL-3.0-only

import "@openzeppelin/contracts/introspection/IERC1820Registry.sol";
import "@openzeppelin/contracts/introspection/ERC1820Implementer.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";
import "./utils/ECDSA.sol";

contract HoprChannels is IERC777Recipient, ERC1820Implementer {
    using SafeMath for uint256;

    // an account has set a new secret hash
    event SecretHashSet(address indexed account, bytes16 secretHash, uint128 counter);

    // the payment channel has been funded

    struct Account {
        bytes16 hashedSecret; // account's hashedSecret
        uint120 counter; // increases everytime 'setHashedSecret' is called by the account
        uint8 oddY;
        uint256 accountX; // second part of account's public key
    }
    enum ChannelStatus {UNINITIALISED, FUNDED, OPEN, PENDING}

    struct Channel {
        uint256 deposit; // tokens in the deposit
        uint256 partyABalance; // tokens that are claimable by party 'A'
        uint128 closureTime; // the time when the channel can be closed by either party
        uint128 stateCounter;
        /* stateCounter mod 10 == 0: uninitialised
         * stateCounter mod 10 == 1: funding
         * stateCounter mod 10 == 2: open
         * stateCounter mod 10 == 3: pending
         */
    }

    // setup ERC1820
    IERC1820Registry internal constant _ERC1820_REGISTRY = IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);
    bytes32 public constant TOKENS_RECIPIENT_INTERFACE_HASH = keccak256("ERC777TokensRecipient");

    // TODO: update this when adding / removing states.
    uint8 constant NUMBER_OF_STATES = 4;

    IERC20 public token; // the token that will be used to settle payments
    uint256 public secsClosure; // seconds it takes to allow closing of channel after channel's -
    // initiated channel closure, in case counter-party does not act -
    // within this time period

    // store accounts' state
    mapping(address => Account) public accounts;

    // store channels' state e.g: channels[hash(party_a, party_b)]
    mapping(bytes32 => Channel) public channels;

    constructor(IERC20 _token, uint256 _secsClosure) public {
        token = _token;
        secsClosure = _secsClosure;

        _ERC1820_REGISTRY.setInterfaceImplementer(address(this), TOKENS_RECIPIENT_INTERFACE_HASH, address(this));
    }

    /**
     * @notice sets caller's hashedSecret
     * @param hashedSecret bytes32 hashedSecret to store
     */
    function setHashedSecret(bytes16 hashedSecret) external {
        require(hashedSecret != bytes16(0), "HoprChannels: hashedSecret is empty");

        Account storage account = accounts[msg.sender];
        require(account.hashedSecret != hashedSecret, "HoprChannels: new and old hashedSecrets are the same");

        account.hashedSecret = hashedSecret;
        account.counter = account.counter += 1;

        emit SecretHashSet(msg.sender, hashedSecret, account.counter);
    }

    function init(
        bytes16 hashedSecret,
        uint256 senderX,
        uint256 senderY
    ) external {
        (, uint8 oddY) = ECDSA.compress(senderX, senderY);

        require(
            ECDSA.compressedPubKeyToEthereumAddress(senderX, oddY) == msg.sender,
            "Given public key must match 'msg.sender'"
        );

        Account storage account = accounts[msg.sender];

        require(
            account.hashedSecret == bytes16(0) &&
                account.counter == uint120(0) &&
                account.oddY == uint8(0) &&
                account.accountX == uint256(0),
            "Account must not be set"
        );

        require(hashedSecret != bytes16(0), "HashedSecret must not be empty.");

        accounts[msg.sender] = Account(hashedSecret, uint120(0), oddY, senderX);

        emit SecretHashSet(msg.sender, hashedSecret, uint128(0));
    }

    /**
     * Fund a channel between 'accountA' and 'accountB',
     * specified tokens must be approved beforehand.
     * Called when HOPR tokens are send to this contract.
     *
     * @notice fund a channel
     * @param recipient address account which the funds are for
     * @param counterParty address the counterParty of 'recipient'
     * @param additionalDeposit uint256 amount to fund the channel
     */
    function fundChannel(
        address funder,
        address recipient,
        address counterParty,
        uint256 additionalDeposit
    ) internal {
        require(recipient != counterParty, "HoprChannels: 'recipient' and 'counterParty' must not be the same");
        require(recipient != address(0), "HoprChannels: 'recipient' address is empty");
        require(counterParty != address(0), "HoprChannels: 'counterParty' address is empty");
        require(additionalDeposit > 0, "HoprChannels: 'additionalDeposit' must be greater than 0");

        (address partyA, , Channel storage channel, ChannelStatus status) = getChannel(recipient, counterParty);

        require(
            status == ChannelStatus.UNINITIALISED || status == ChannelStatus.FUNDED,
            "HoprChannels: channel must be 'UNINITIALISED' or 'FUNDED'"
        );

        channel.deposit = channel.deposit.add(additionalDeposit);

        if (recipient == partyA) {
            channel.partyABalance = channel.partyABalance.add(additionalDeposit);
        }

        if (status == ChannelStatus.UNINITIALISED) {
            // The state counter indicates the recycling generation and ensures that both parties are using the correct generation.
            channel.stateCounter += 1;
        }

        emitFundedChannel(funder, recipient, counterParty, additionalDeposit, 0);
    }

    /**
     * Fund a channel between 'initiator' and 'counterParty' using a signature,
     * specified tokens must be approved beforehand.
     *
     * @notice fund a channel
     * @param stateCounter uint128
     * @param additionalDeposit uint256
     * @param partyAAmount uint256
     * @param not_after uint256
     * @param r bytes32
     * @param s bytes32
     * @param v uint8
     */
    function fundChannelWithSig(
        uint256 additionalDeposit,
        uint256 partyAAmount,
        uint256 not_after,
        bytes32 r,
        bytes32 s,
        uint8 v,
        uint120 stateCounter
    ) external {
        address initiator = msg.sender;

        // verification
        require(additionalDeposit > 0, "HoprChannels: 'additionalDeposit' must be strictly greater than zero");
        require(
            partyAAmount <= additionalDeposit,
            "HoprChannels: 'partyAAmount' must be strictly smaller than 'additionalDeposit'"
        );
        require(not_after >= now, "HoprChannels: signature must not be expired");

        address counterparty = ECDSA.recover(
            ECDSA.toEthSignedMessageHash(
                "160",
                abi.encode(stateCounter, initiator, additionalDeposit, partyAAmount, not_after)
            ),
            r,
            s,
            v
        );

        require(initiator != counterparty, "HoprChannels: initiator and counterparty must not be the same");

        (address partyA, , Channel storage channel, ChannelStatus status) = getChannel(initiator, counterparty);

        require(
            channel.stateCounter == stateCounter,
            "HoprChannels: stored stateCounter and signed stateCounter must be the same"
        );

        require(
            status == ChannelStatus.UNINITIALISED || status == ChannelStatus.FUNDED,
            "HoprChannels: channel must be 'UNINITIALISED' or 'FUNDED'"
        );

        uint256 partyBAmount = additionalDeposit - partyAAmount;

        if (initiator == partyA) {
            token.transferFrom(initiator, address(this), partyAAmount);
            token.transferFrom(counterparty, address(this), partyBAmount);
        } else {
            token.transferFrom(initiator, address(this), partyBAmount);
            token.transferFrom(counterparty, address(this), partyAAmount);
        }

        channel.deposit = additionalDeposit;
        channel.partyABalance = partyAAmount;

        if (status == ChannelStatus.UNINITIALISED) {
            // The state counter indicates the recycling generation and ensures that both parties are using the correct generation.
            channel.stateCounter += 1;
        }

        if (initiator == partyA) {
            emitFundedChannel(address(0), initiator, counterparty, partyAAmount, partyBAmount);
        } else {
            emitFundedChannel(address(0), counterparty, initiator, partyAAmount, partyBAmount);
        }
    }

    /**
     * @notice open a channel
     * @param counterparty address the counterParty of 'msg.sender'
     */
    function openChannel(address counterparty) public {
        address opener = msg.sender;

        require(opener != counterparty, "HoprChannels: 'opener' and 'counterParty' must not be the same");
        require(counterparty != address(0), "HoprChannels: 'counterParty' address is empty");

        (, , Channel storage channel, ChannelStatus status) = getChannel(opener, counterparty);

        require(status == ChannelStatus.FUNDED, "HoprChannels: channel must be in 'FUNDED' state");

        // The state counter indicates the recycling generation and ensures that both parties are using the correct generation.
        channel.stateCounter += 1;

        emitOpenedChannel(opener, counterparty);
    }

    /**
     * @notice redeem ticket
     * @param preImage bytes32 the value that once hashed produces recipients hashedSecret
     * @param hashedSecretASecretB bytes32 hash of secretA concatenated with secretB
     * @param amount uint256 amount 'msg.sender' will receive
     * @param winProb bytes32 win probability
     * @param r bytes32
     * @param s bytes32
     * @param v uint8
     */
    function redeemTicket(
        bytes16 preImage,
        bytes32 channelId,
        bytes32 hashedSecretASecretB,
        uint256 amount,
        bytes32 winProb,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) public {
        Account storage recipientAccount = accounts[msg.sender];

        bytes32 challenge = keccak256(abi.encodePacked(hashedSecretASecretB));

        bytes32 hashedTicket = ECDSA.toEthSignedMessageHash(
            "192",
            abi.encode(channelId, challenge, recipientAccount.hashedSecret, recipientAccount.counter, amount, winProb)
        );

        bytes32 luck = keccak256(abi.encode(hashedTicket, preImage));

        require(uint256(luck) < uint256(winProb), "HoprChannels: ticket must be a win");

        (address partyA, , Channel storage channel, ChannelStatus status) = getChannel(
            msg.sender,
            ECDSA.recover(hashedTicket, r, s, v)
        );

        require(
            status == ChannelStatus.OPEN || status == ChannelStatus.PENDING,
            "HoprChannels: channel must be 'OPEN' or 'PENDING'"
        );

        require(amount > 0, "HoprChannels: amount must be strictly greater than zero");

        require(
            recipientAccount.hashedSecret == bytes16(keccak256(abi.encodePacked(preImage))),
            "HoprChannels: given value is not a pre-image of the stored on-chain secret"
        );

        recipientAccount.hashedSecret = preImage;

        if (msg.sender == partyA) {
            channel.partyABalance = channel.partyABalance.add(amount);
        } else {
            channel.partyABalance = channel.partyABalance.sub(amount);
        }

        require(
            channel.partyABalance <= channel.deposit,
            "HoprChannels: partyABalance must be strictly smaller than deposit balance"
        );
    }

    /**
     * A channel's party can initiate channel closure at any time,
     * it starts a timeout.
     *
     * @notice initiate channel's closure
     * @param counterparty address counter party of 'msg.sender'
     */
    function initiateChannelClosure(address counterparty) external {
        address initiator = msg.sender;

        (, , Channel storage channel, ChannelStatus status) = getChannel(initiator, counterparty);

        require(status == ChannelStatus.OPEN, "HoprChannels: channel must be 'OPEN'");

        channel.closureTime = uint128(now + secsClosure);
        // The state counter indicates the recycling generation and ensures that both parties are using the correct generation.
        channel.stateCounter += 1;

        emitInitiatedChannelClosure(initiator, counterparty, channel.closureTime);
    }

    /**
     * If the timeout is reached without the 'counterParty' reedeming a ticket,
     * then the tokens can be claimed by 'msg.sender'.
     *
     * @notice claim channel's closure
     * @param counterparty address counter party of 'msg.sender'
     */
    function claimChannelClosure(address counterparty) external {
        address initiator = msg.sender;

        (address party_a, address party_b, Channel storage channel, ChannelStatus status) = getChannel(
            initiator,
            counterparty
        );

        require(status == ChannelStatus.PENDING, "HoprChannels: channel must be 'PENDING'");
        require(now >= channel.closureTime, "HoprChannels: 'closureTime' has not passed");

        // settle balances
        if (channel.partyABalance > 0) {
            token.transfer(party_a, channel.partyABalance);
            channel.deposit = channel.deposit.sub(channel.partyABalance);
        }

        if (channel.deposit > 0) {
            token.transfer(party_b, channel.deposit);
        }

        emitClosedChannel(initiator, counterparty, channel.partyABalance, channel.deposit);

        delete channel.deposit;
        delete channel.partyABalance;
        delete channel.closureTime;
        // The state counter indicates the recycling generation and ensures that both parties are using the correct generation.
        // Increase state counter so that we can re-use the same channel after it has been closed.
        channel.stateCounter += 7;
    }

    /**
     * A hook triggered when HOPR tokens are send to this contract.
     *
     * @param operator address operator requesting the transfer
     * @param from address token holder address
     * @param to address recipient address
     * @param amount uint256 amount of tokens to transfer
     * @param userData bytes extra information provided by the token holder (if any)
     * @param operatorData bytes extra information provided by the operator (if any)
     */
    function tokensReceived(
        address operator,
        address from,
        // solhint-disable-next-line no-unused-vars
        address to,
        uint256 amount,
        bytes calldata userData,
        // solhint-disable-next-line no-unused-vars
        bytes calldata operatorData
    ) external override {
        require(msg.sender == address(token), "HoprChannels: Invalid token");

        // only call 'fundChannel' when the operator is not self
        if (operator != address(this)) {
            (address recipient, address counterParty) = abi.decode(userData, (address, address));

            fundChannel(from, recipient, counterParty, amount);
        }
    }

    /**
     * @notice returns channel data
     * @param accountA address of account 'A'
     * @param accountB address of account 'B'
     */
    function getChannel(address accountA, address accountB)
        internal
        view
        returns (
            address,
            address,
            Channel storage,
            ChannelStatus
        )
    {
        (address partyA, address partyB) = getParties(accountA, accountB);
        bytes32 channelId = getChannelId(partyA, partyB);
        Channel storage channel = channels[channelId];
        ChannelStatus status = getChannelStatus(channel);

        return (partyA, partyB, channel, status);
    }

    /**
     * @notice return true if accountA is party_a
     * @param accountA address of account 'A'
     * @param accountB address of account 'B'
     */
    function isPartyA(address accountA, address accountB) internal pure returns (bool) {
        return uint160(accountA) < uint160(accountB);
    }

    /**
     * @notice return party_a and party_b
     * @param accountA address of account 'A'
     * @param accountB address of account 'B'
     */
    function getParties(address accountA, address accountB) internal pure returns (address, address) {
        if (isPartyA(accountA, accountB)) {
            return (accountA, accountB);
        } else {
            return (accountB, accountA);
        }
    }

    /**
     * @notice return channel id
     * @param party_a address of party 'A'
     * @param party_b address of party 'B'
     */
    function getChannelId(address party_a, address party_b) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(party_a, party_b));
    }

    /**
     * @notice returns 'ChannelStatus'
     * @param channel Channel
     */
    function getChannelStatus(Channel memory channel) internal pure returns (ChannelStatus) {
        return ChannelStatus(channel.stateCounter % 10);
    }

    /**
     * @dev Emits a FundedChannel event that contains the public keys of recipient
     * and counterparty as compressed EC-points.
     */
    function emitFundedChannel(
        address funder,
        address recipient,
        address counterparty,
        uint256 recipientAmount,
        uint256 counterpartyAmount
    ) private {
        /* FundedChannel(
         *   address funder,
         *   uint256 indexed recipient,
         *   uint256 indexed counterParty,
         *   uint256 recipientAmount,
         *   uint256 counterPartyAmount
         * )
         */
        bytes32 FundedChannel = keccak256("FundedChannel(address,uint,uint,uint,uint)");

        Account storage recipientAccount = accounts[recipient];
        Account storage counterpartyAccount = accounts[counterparty];

        uint256 recipientX = recipientAccount.accountX;
        uint8 recipientOddY = recipientAccount.oddY;

        uint256 counterpartyX = counterpartyAccount.accountX;
        uint8 counterpartyOddY = counterpartyAccount.oddY;
        assembly {
            let topic0 := or(or(shl(2, shr(2, FundedChannel)), shl(1, recipientOddY)), counterpartyOddY)

            let memPtr := mload(0x40)

            mstore(memPtr, recipientAmount)
            mstore(add(memPtr, 0x20), counterpartyAmount)
            mstore(add(memPtr, 0x40), funder)

            log3(memPtr, 0x60, topic0, recipientX, counterpartyX)
        }
    }

    /**
     * @dev Emits a OpenedChannel event that contains the public keys of opener
     * and counterparty as compressed EC-points.
     */
    function emitOpenedChannel(address opener, address counterparty) private {
        /* OpenedChannel(
         *   uint256 indexed opener,
         *   uint256 indexed counterParty
         * )
         */
        bytes32 OpenedChannel = keccak256("OpenedChannel(uint,uint)");

        Account storage openerAccount = accounts[opener];
        Account storage counterpartyAccount = accounts[counterparty];

        uint256 openerX = openerAccount.accountX;
        uint8 openerOddY = openerAccount.oddY;

        uint256 counterpartyX = counterpartyAccount.accountX;
        uint8 counterpartyOddY = counterpartyAccount.oddY;
        assembly {
            let topic0 := or(or(shl(2, shr(2, OpenedChannel)), shl(1, openerOddY)), counterpartyOddY)

            log3(0x00, 0x00, topic0, openerX, counterpartyX)
        }
    }

    /**
     * @dev Emits a InitiatedChannelClosure event that contains the public keys of initiator
     * and counterparty as compressed EC-points.
     */
    function emitInitiatedChannelClosure(
        address initiator,
        address counterparty,
        uint256 closureTime
    ) private {
        /* InitiatedChannelClosure(
         *   uint256 indexed initiator,
         *   uint256 indexed counterParty,
         *   uint256 closureTime
         * )
         */
        bytes32 InitiatedChannelClosure = keccak256("InitiatedChannelClosure(uint,uint,uint)");

        Account storage initiatorAccount = accounts[initiator];
        Account storage counterpartyAccount = accounts[counterparty];

        uint256 initiatorX = initiatorAccount.accountX;
        uint8 initiatorOddY = initiatorAccount.oddY;

        uint256 counterpartyX = counterpartyAccount.accountX;
        uint8 counterpartyOddY = counterpartyAccount.oddY;

        assembly {
            let topic0 := or(or(shl(2, shr(2, InitiatedChannelClosure)), shl(1, initiatorOddY)), counterpartyOddY)

            let memPtr := mload(0x40)

            mstore(memPtr, closureTime)

            log3(memPtr, 0x20, topic0, initiatorX, counterpartyX)
        }
    }

    /**
     * @dev Emits a ClosedChannel event that contains the public keys of initiator
     * and counterparty as compressed EC-points.
     */
    function emitClosedChannel(
        address initiator,
        address counterparty,
        uint256 partyAAmount,
        uint256 partyBAmount
    ) private {
        /*
         * ClosedChannel(
         *   uint256 indexed initiator,
         *   uint256 indexed counterParty,
         *   uint256 partyAAmount,
         *   uint256 partyBAmount
         */
        bytes32 ClosedChannel = keccak256("InitiatedChannelClosure(uint,uint,uint,uint)");

        Account storage initiatorAccount = accounts[initiator];
        Account storage counterpartyAccount = accounts[counterparty];

        uint256 initiatorX = initiatorAccount.accountX;
        uint8 initiatorOddY = initiatorAccount.oddY;

        uint256 counterpartyX = counterpartyAccount.accountX;
        uint8 counterpartyOddY = counterpartyAccount.oddY;

        assembly {
            let topic0 := or(or(shl(2, shr(2, ClosedChannel)), shl(1, initiatorOddY)), counterpartyOddY)

            let memPtr := mload(0x40)

            mstore(memPtr, partyAAmount)
            mstore(add(0x20, memPtr), partyBAmount)

            log3(memPtr, 0x40, topic0, initiatorX, counterpartyX)
        }
    }
}
