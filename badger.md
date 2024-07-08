# QA Report

## [L-01] Insecure Balance Accounting of Balance in Multiple Functions
In functions like  `_depositRawEthIntoLido`, `_convertWrappedEthToStETH`, `_openCdp`, `_closeCdp`, `_openCdpWithPermit`, `_adjustCdpWithPermit`, `_convertWstEthToStETH`, `_convertWstEthToStETH` and `_transferInitialStETHFromCaller`,
where the implementation relies on checking balance differences before and after operations to find the amount of ETH or WETH deposited, converted, or transferred. 
This method is susceptible to manipulation if additional ETH or WETH is sent to the contract just before or during the execution of these functions.

### Impact
This vulnerability can lead to inaccurate accounting of ETH or WETH amounts, allowing an attacker to potentially exploit the system by, inflating the perceived amount of deposited ETH or WETH. 
And manipulating the balance checks to their advantage.

https://github.com/code-423n4/2024-06-badger/blob/main/ebtc-zap-router/src/ZapRouterBase.sol#L34-L52
```solidity
    function _depositRawEthIntoLido(uint256 _initialETH) internal returns (uint256) {
        // check before-after balances for 1-wei corner case
        uint256 _balBefore = stEth.balanceOf(address(this));
        // TODO call submit() with a referral?
        payable(address(stEth)).call{value: _initialETH}("");
@>      uint256 _deposit = stEth.balanceOf(address(this)) - _balBefore;
        return _deposit;
    }

    function _convertWrappedEthToStETH(uint256 _initialWETH) internal returns (uint256) {
        uint256 _wETHBalBefore = wrappedEth.balanceOf(address(this));
        wrappedEth.transferFrom(msg.sender, address(this), _initialWETH);
@>      uint256 _wETHReiceived = wrappedEth.balanceOf(address(this)) - _wETHBalBefore;

        uint256 _rawETHBalBefore = address(this).balance;
        IWrappedETH(address(wrappedEth)).withdraw(_wETHReiceived);
@>      uint256 _rawETHConverted = address(this).balance - _rawETHBalBefore;
        return _depositRawEthIntoLido(_rawETHConverted);
    }
```

## [L-02] Unused Parameter in `EbtcLeverageZapRouter::_openCdp`
Function `_openCdp` includes a parameter `_stEthMarginAmount` which is not used within the function body. Including unused parameters can lead to confusion or indicate that there might be incomplete functionality.
Or explicitly state in the comments why _stEthMarginAmount is not utilized.

https://github.com/code-423n4/2024-06-badger/blob/main/ebtc-zap-router/src/EbtcLeverageZapRouter.sol#L205-L248
```solidity
function _openCdp(
        uint256 _debt,
        bytes32 _upperHint,
        bytes32 _lowerHint,
        uint256 _stEthLoanAmount,
   @>   uint256 _stEthMarginAmount,
        uint256 _stEthDepositAmount,
        bytes calldata _positionManagerPermit,
        TradeData calldata _tradeData
    ) internal nonReentrant returns (bytes32 cdpId) {
        
        _requireZeroOrMinAdjustment(_debt);
        _requireAtLeastMinNetStEthBalance(_stEthDepositAmount - LIQUIDATOR_REWARD);

        // _positionManagerPermit is only required if called directly
        // for 3rd party integrations (i.e. DeFi saver, instadapp), setPositionManagerApproval
        // can be used before and after each operation
        if (_positionManagerPermit.length > 0) {
            PositionManagerPermit memory approval = abi.decode(_positionManagerPermit, (PositionManagerPermit));
            _permitPositionManagerApproval(borrowerOperations, approval);
        }

        // pre-compute cdpId for post checks
        cdpId = sortedCdps.toCdpId(msg.sender, block.number, sortedCdps.nextCdpNonce());

        OpenCdpForOperation memory cdp;

        cdp.eBTCToMint = _debt;
        cdp._upperHint = _upperHint;
        cdp._lowerHint = _lowerHint;
        cdp.stETHToDeposit = _stEthDepositAmount;
        cdp.borrower = msg.sender;

        _openCdpOperation({
            _cdpId: cdpId,
            _cdp: cdp,
            _flAmount: _stEthLoanAmount,
            _tradeData: _tradeData
        });

        if (_positionManagerPermit.length > 0) {
            borrowerOperations.renouncePositionManagerApproval(msg.sender);
        }
    }
```

## [L-03] `ZapRouterBase::_requireZeroOrMinAdjustment` Should Be Marked as `pure`

Function `_requireZeroOrMinAdjustment` does not read any state variables. It only checks the value of `_change` against a constant `MIN_CHANGE` and throws an error if the condition is not met. 
Since it does not read/write on any state variables, it can be safely marked as pure.

https://github.com/code-423n4/2024-06-badger/blob/main/ebtc-zap-router/src/ZapRouterBase.sol#L135-L140
```solidity
    function _requireZeroOrMinAdjustment(uint256 _change) internal view {
        require(
            _change == 0 || _change >= MIN_CHANGE,
            "ZapRouterBase: Debt or collateral change must be zero or above min"
        );
    }
```

## [L-04] Error Message in Require for `LeverageMacroBase::_doCheckValueType` is incorrect
The function `_doCheckValueType` contains an incorrect message in its require statement, `require(check.value <= valueToCheck, "!LeverageMacroReference: let post check")` where the message mentions `"!LeverageMacroReference: let post check"` instead of `"!LeverageMacroReference: lte post check"`

https://github.com/code-423n4/2024-06-badger/blob/main/ebtc-protocol/packages/contracts/contracts/LeverageMacroBase.sol#L277-L290
```solidity
    function _doCheckValueType(CheckValueAndType memory check, uint256 valueToCheck) internal {
        if (check.operator == Operator.skip) {
            // Early return
            return;
        } else if (check.operator == Operator.gte) {
            require(check.value >= valueToCheck, "!LeverageMacroReference: gte post check");
        } else if (check.operator == Operator.lte) {
@>         require(check.value <= valueToCheck, "!LeverageMacroReference: let post check");
        } else if (check.operator == Operator.equal) {
            require(check.value == valueToCheck, "!LeverageMacroReference: equal post check");
        } else {
            revert("Operator not found");
        }
    }
```

## [L-05] Parameter Validation Missing in `ZapRouterBase::_convertWrappedEthToStETH`
`_convertWrappedEthToStETH` function does not include a check to ensure `_initialWETH` is non-zero before proceeding with the transaction. 
if `_initialWETH` is passed as zero could potentially lead to unintentionally/unexpected behavior.

https://github.com/code-423n4/2024-06-badger/blob/main/ebtc-zap-router/src/ZapRouterBase.sol#L43-L52
```solidity
    function _convertWrappedEthToStETH(uint256 _initialWETH) internal returns (uint256) {
        uint256 _wETHBalBefore = wrappedEth.balanceOf(address(this));
        wrappedEth.transferFrom(msg.sender, address(this), _initialWETH);
        uint256 _wETHReiceived = wrappedEth.balanceOf(address(this)) - _wETHBalBefore;

        uint256 _rawETHBalBefore = address(this).balance;
        IWrappedETH(address(wrappedEth)).withdraw(_wETHReiceived);
        uint256 _rawETHConverted = address(this).balance - _rawETHBalBefore;
        return _depositRawEthIntoLido(_rawETHConverted);
    }
```
## [L-06] Typo in Variable Name in `_convertWrappedEthToStETH` and `_convertWstEthToStETH` Function
The variable name `_wETHReiceived` appears to be a typo and should be corrected to `_wETHReceived`. In functions  `_convertWrappedEthToStETH` and `_convertWstEthToStETH`, a total of four instances.


## [L-07] Irrelevant Unchecked loop increments if using Solidity 0.8.22
Solidity 0.8.22 introduces an overflow check optimization that automatically generates an unchecked arithmetic increment of the counter of for loops. 
This new optimization removes the need for poor unchecked increment patterns in for loop bodies. <br>
Ref: https://soliditylang.org/blog/2023/10/25/solidity-0.8.22-release-announcement/

## [L-08] Inline Comments Can Be Improved For Consistency
In `LeverageMacroBase::_doOperation`, for the post checks for openCdp it uses multi-line comments whereas for other update and close cdp inline comments are used.

https://github.com/code-423n4/2024-06-badger/blob/main/ebtc-protocol/packages/contracts/contracts/LeverageMacroBase.sol#L204-L238
```solidity
        /**
         * POST CALL CHECK FOR CREATION
         */
        if (postCheckType == PostOperationCheck.openCdp) {
            // Check for param details
            ICdpManagerData.Cdp memory cdpInfo = cdpManager.Cdps(expectedCdpId);
            _doCheckValueType(checkParams.expectedDebt, cdpInfo.debt);
            _doCheckValueType(checkParams.expectedCollateral, cdpInfo.coll);
            require(
                cdpInfo.status == checkParams.expectedStatus,
                "!LeverageMacroReference: openCDP status check"
            );
        }

        // Update CDP, Ensure the stats are as intended
        if (postCheckType == PostOperationCheck.cdpStats) {
            ICdpManagerData.Cdp memory cdpInfo = cdpManager.Cdps(checkParams.cdpId);

            _doCheckValueType(checkParams.expectedDebt, cdpInfo.debt);
            _doCheckValueType(checkParams.expectedCollateral, cdpInfo.coll);
            require(
                cdpInfo.status == checkParams.expectedStatus,
                "!LeverageMacroReference: adjustCDP status check"
            );
        }

        // Post check type: Close, ensure it has the status we want
        if (postCheckType == PostOperationCheck.isClosed) {
            ICdpManagerData.Cdp memory cdpInfo = cdpManager.Cdps(checkParams.cdpId);

            require(
                cdpInfo.status == checkParams.expectedStatus,
                "!LeverageMacroReference: closeCDP status check"
            );
        }
```

## [L-09] Lack of Validation for Parameters in Constructor 
The constructors of `ZapRouterBase`, `LeverageMacroBase`, and `LeverageZapRouterBase` do not perform any validation on their parameters. If validation is not applicable for a specific parameter, then it can be commented as N/A.
By performing validation on constructor parameters, you can catch potential issues early and prevent unexpected attacks, such as the Clipboard Replacement Attack.

## [L-10] Missing of NatSpec Docs in Some Contracts
The contracts `LeverageZapRouterBase` and `ZapRouterBase` do not have any NatSpec documentation for any of the functions, and the `LeverageMacroBase` has incomplete NatSpec documentation for its functions. NatSpec comments are essential for improving the readability and maintainability of the codebase. They allow developers, users, and auditors to easily understand the functionality of the contract.

## [L-11] Insecure ETH Transfer Method 

Function `_depositRawEthIntoLido` uses a low-level call to transfer ETH, which can be insecure and error-prone. Can use `transfer` or `send`, which automatically revert on failure. 
Or do something like this:

```solidity
    (bool success, ) = payable(address(stEth)).call{value: _initialETH}("");
    require(success, "ETH transfer failed");
```

## [L-12] Order of functions
The solidity [documentation](https://docs.soliditylang.org/en/v0.8.16/style-guide.html#order-of-functions) recommends the following order for functions:
- constructor
- receive function (if exists)
- fallback function (if exists)
- external
- public
- internal
- private

The `receive` function in `EbtcLeverageZapRouter` is between two `external` functions, and not after the constructor. Whereas in `EbtcZapRouter` the `receive` function aligned correctly to the order. 
Ordering helps readers identify which functions they can call and to find the constructor and receive/fallback definitions more easily.
