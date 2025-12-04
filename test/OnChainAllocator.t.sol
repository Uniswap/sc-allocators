// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from 'forge-std/Test.sol';

import {ERC20Mock} from 'src/test/ERC20Mock.sol';

import {TheCompact} from '@uniswap/the-compact/TheCompact.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';

import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {ISignatureTransfer} from 'permit2/src/interfaces/ISignatureTransfer.sol';

import {IOnChainAllocation} from '@uniswap/the-compact/interfaces/IOnChainAllocation.sol';
import {OnChainAllocator} from 'src/allocators/OnChainAllocator.sol';
import {IOnChainAllocator} from 'src/interfaces/IOnChainAllocator.sol';

import {DepositDetails} from '@uniswap/the-compact/types/DepositDetails.sol';
import {
    BATCH_COMPACT_TYPEHASH,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FIVE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_SIX,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO,
    LOCK_TYPEHASH,
    Lock
} from '@uniswap/the-compact/types/EIP712Types.sol';

import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {ResetPeriod} from '@uniswap/the-compact/types/ResetPeriod.sol';
import {Scope} from '@uniswap/the-compact/types/Scope.sol';

import {IERC1271} from '@uniswap/the-compact/../lib/permit2/src/interfaces/IERC1271.sol';
import {IdLib} from '@uniswap/the-compact/lib/IdLib.sol';
import {AlwaysOKAllocator} from '@uniswap/the-compact/test/AlwaysOKAllocator.sol';

import {BatchClaim} from '@uniswap/the-compact/types/BatchClaims.sol';
import {Claim} from '@uniswap/the-compact/types/Claims.sol';
import {BatchClaimComponent, Component} from '@uniswap/the-compact/types/Components.sol';
import {AllocatorLib} from 'src/allocators/lib/AllocatorLib.sol';
import {OnChainAllocationCaller} from 'src/test/OnChainAllocationCaller.sol';

import {DeployTheCompact} from 'test/util/DeployTheCompact.sol';
import {TestHelper} from 'test/util/TestHelper.sol';

contract OnChainAllocatorFactory {
    function deploy(bytes32 salt) external returns (address) {
        return address(new OnChainAllocator{salt: salt}());
    }
}

contract OnChainAllocatorTest is Test, TestHelper {
    TheCompact internal compact;
    OnChainAllocator internal allocator;

    address internal arbiter;
    address internal user;
    uint256 internal userPK;

    ERC20Mock internal usdc;
    ERC20Mock internal dai;

    address internal recipient;
    address internal caller;
    uint256 internal callerPK;

    OnChainAllocationCaller internal allocationCaller;

    uint256 internal defaultAmount;
    uint32 internal defaultExpiration;

    uint256 defaultNonce;

    // For reentrancy testing
    MaliciousRecipient internal maliciousRecipient;

    // Permit2 constants
    address constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    bytes32 constant PERMIT2_DOMAIN_SEPARATOR_TYPEHASH =
        keccak256('EIP712Domain(string name,uint256 chainId,address verifyingContract)');
    bytes32 constant TOKEN_PERMISSIONS_TYPEHASH = keccak256('TokenPermissions(address token,uint256 amount)');

    // BatchActivation typehash (from the-compact/src/types/EIP712Types.sol)
    bytes32 constant BATCH_COMPACT_BATCH_ACTIVATION_TYPEHASH =
        0xa794ed1a28cdf297ac45a3eee4643e35d29b295a389368da5f6baa420872c9b7;

    // PermitBatchWitnessTransferFrom typehash
    string constant PERMIT_BATCH_WITNESS_TYPESTRING =
        'PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,BatchActivation witness)BatchActivation(address activator,uint256[] ids,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments)Lock(bytes12 lockTag,address token,uint256 amount)TokenPermissions(address token,uint256 amount)';
    bytes32 constant PERMIT_BATCH_WITNESS_TYPEHASH = keccak256(bytes(PERMIT_BATCH_WITNESS_TYPESTRING));

    function setUp() public {
        // Deploy TheCompact at the hardcoded address used by Utility.sol
        // This is necessary because OnChainAllocator now inherits from Utility
        // which requires THE_COMPACT (0x00000000000000171ede64904551eeDF3C6C9788) to exist
        compact = DeployTheCompact(new DeployTheCompact()).deployTheCompact();
        assertEq(address(compact), address(0x00000000000000171ede64904551eeDF3C6C9788));

        // Deploy Permit2 at the expected address
        _deployPermit2();

        arbiter = makeAddr('arbiter');
        (user, userPK) = makeAddrAndKey('user');
        allocator = new OnChainAllocator();

        usdc = new ERC20Mock('USDC', 'USDC');
        dai = new ERC20Mock('DAI', 'DAI');

        recipient = makeAddr('recipient');
        (caller, callerPK) = makeAddrAndKey('caller');
        allocationCaller = new OnChainAllocationCaller(address(allocator), address(compact));
        deal(user, 10 ether);
        usdc.mint(user, 10 ether);
        dai.mint(user, 10 ether);

        // Approve Permit2 for tokens
        vm.startPrank(user);
        usdc.approve(PERMIT2, type(uint256).max);
        dai.approve(PERMIT2, type(uint256).max);
        vm.stopPrank();

        defaultAmount = 1 ether;
        defaultExpiration = uint32(block.timestamp + 300); // 5 minutes fits 10-minute reset period
        defaultNonce = _composeNonceUint(user, 1);

        // Setup malicious recipient for reentrancy tests
        maliciousRecipient = new MaliciousRecipient(address(allocator), address(compact), address(allocationCaller));
    }

    function _deployPermit2() internal {
        // Deploy Permit2 using the same pattern as the-compact tests
        address permit2Deployer = address(0x4e59b44847b379578588920cA78FbF26c0B4956C);
        address permit2DeployerDeployer = address(0x3fAB184622Dc19b6109349B94811493BF2a45362);
        bytes memory permit2DeployerCreationCode =
            hex'604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3';

        vm.deal(permit2DeployerDeployer, 1e18);
        vm.prank(permit2DeployerDeployer);
        address deployedPermit2Deployer;
        assembly ("memory-safe") {
            deployedPermit2Deployer :=
                create(0, add(permit2DeployerCreationCode, 0x20), mload(permit2DeployerCreationCode))
        }

        bytes memory permit2CreationCalldata =
            hex'0000000000000000000000000000000000000000d3af2663da51c1021500000060c0346100bb574660a052602081017f8cad95687ba82c2ce50e74f7b754645e5117c3a5bec8151c0726d5857980a86681527f9ac997416e8ff9d2ff6bebeb7149f65cdae5e32e2b90440b566bb3044041d36a60408301524660608301523060808301526080825260a082019180831060018060401b038411176100a557826040525190206080526123c090816100c1823960805181611b47015260a05181611b210152f35b634e487b7160e01b600052604160045260246000fd5b600080fdfe6040608081526004908136101561001557600080fd5b600090813560e01c80630d58b1db1461126c578063137c29fe146110755780632a2d80d114610db75780632b67b57014610bde57806330f28b7a14610ade5780633644e51514610a9d57806336c7851614610a285780633ff9dcb1146109a85780634fe02b441461093f57806365d9723c146107ac57806387517c451461067a578063927da105146105c3578063cc53287f146104a3578063edd9444b1461033a5763fe8ec1a7146100c657600080fd5b346103365760c07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126103365767ffffffffffffffff833581811161033257610114903690860161164b565b60243582811161032e5761012b903690870161161a565b6101336114e6565b9160843585811161032a5761014b9036908a016115c1565b98909560a43590811161032657610164913691016115c1565b969095815190610173826113ff565b606b82527f5065726d697442617463685769746e6573735472616e7366657246726f6d285460208301527f6f6b656e5065726d697373696f6e735b5d207065726d69747465642c61646472838301527f657373207370656e6465722c75696e74323536206e6f6e63652c75696e74323560608301527f3620646561646c696e652c000000000000000000000000000000000000000000608083015282519a8b9181610222602085018096611f93565b918237018a8152039961025b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09b8c8101835282611437565b5190209085515161026b81611ebb565b908a5b8181106102f95750506102f6999a6102ed9183516102a081610294602082018095611f66565b03848101835282611437565b519020602089810151858b015195519182019687526040820192909252336060820152608081019190915260a081019390935260643560c08401528260e081015b03908101835282611437565b51902093611cf7565b80f35b8061031161030b610321938c5161175e565b51612054565b61031b828661175e565b52611f0a565b61026e565b8880fd5b8780fd5b8480fd5b8380fd5b5080fd5b5091346103365760807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126103365767ffffffffffffffff9080358281116103325761038b903690830161164b565b60243583811161032e576103a2903690840161161a565b9390926103ad6114e6565b9160643590811161049f576103c4913691016115c1565b949093835151976103d489611ebb565b98885b81811061047d5750506102f697988151610425816103f9602082018095611f66565b037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe08101835282611437565b5190206020860151828701519083519260208401947ffcf35f5ac6a2c28868dc44c302166470266239195f02b0ee408334829333b7668652840152336060840152608083015260a082015260a081526102ed8161141b565b808b61031b8261049461030b61049a968d5161175e565b9261175e565b6103d7565b8680fd5b5082346105bf57602090817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126103325780359067ffffffffffffffff821161032e576104f49136910161161a565b929091845b848110610504578580f35b8061051a610515600193888861196c565b61197c565b61052f84610529848a8a61196c565b0161197c565b3389528385528589209173ffffffffffffffffffffffffffffffffffffffff80911692838b528652868a20911690818a5285528589207fffffffffffffffffffffffff000000000000000000000000000000000000000081541690558551918252848201527f89b1add15eff56b3dfe299ad94e01f2b52fbcb80ae1a3baea6ae8c04cb2b98a4853392a2016104f9565b8280fd5b50346103365760607ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261033657610676816105ff6114a0565b936106086114c3565b6106106114e6565b73ffffffffffffffffffffffffffffffffffffffff968716835260016020908152848420928816845291825283832090871683528152919020549251938316845260a083901c65ffffffffffff169084015260d09190911c604083015281906060820190565b0390f35b50346103365760807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc360112610336576106b26114a0565b906106bb6114c3565b916106c46114e6565b65ffffffffffff926064358481169081810361032a5779ffffffffffff0000000000000000000000000000000000000000947fda9fa7c1b00402c17d0161b249b1ab8bbec047c5a52207b9c112deffd817036b94338a5260016020527fffffffffffff0000000000000000000000000000000000000000000000000000858b209873ffffffffffffffffffffffffffffffffffffffff809416998a8d5260205283878d209b169a8b8d52602052868c209486156000146107a457504216925b8454921697889360a01b16911617179055815193845260208401523392a480f35b905092610783565b5082346105bf5760607ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126105bf576107e56114a0565b906107ee6114c3565b9265ffffffffffff604435818116939084810361032a57338852602091600183528489209673ffffffffffffffffffffffffffffffffffffffff80911697888b528452858a20981697888a5283528489205460d01c93848711156109175761ffff9085840316116108f05750907f55eb90d810e1700b35a8e7e25395ff7f2b2259abd7415ca2284dfb1c246418f393929133895260018252838920878a528252838920888a5282528389209079ffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffff000000000000000000000000000000000000000000000000000083549260d01b16911617905582519485528401523392a480f35b84517f24d35a26000000000000000000000000000000000000000000000000000000008152fd5b5084517f756688fe000000000000000000000000000000000000000000000000000000008152fd5b503461033657807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc360112610336578060209273ffffffffffffffffffffffffffffffffffffffff61098f6114a0565b1681528084528181206024358252845220549051908152f35b5082346105bf57817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126105bf577f3704902f963766a4e561bbaab6e6cdc1b1dd12f6e9e99648da8843b3f46b918d90359160243533855284602052818520848652602052818520818154179055815193845260208401523392a280f35b8234610a9a5760807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc360112610a9a57610a606114a0565b610a686114c3565b610a706114e6565b6064359173ffffffffffffffffffffffffffffffffffffffff8316830361032e576102f6936117a1565b80fd5b503461033657817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261033657602090610ad7611b1e565b9051908152f35b508290346105bf576101007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126105bf57610b1a3661152a565b90807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7c36011261033257610b4c611478565b9160e43567ffffffffffffffff8111610bda576102f694610b6f913691016115c1565b939092610b7c8351612054565b6020840151828501519083519260208401947f939c21a48a8dbe3a9a2404a1d46691e4d39f6583d6ec6b35714604c986d801068652840152336060840152608083015260a082015260a08152610bd18161141b565b51902091611c25565b8580fd5b509134610336576101007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261033657610c186114a0565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc360160c08112610332576080855191610c51836113e3565b1261033257845190610c6282611398565b73ffffffffffffffffffffffffffffffffffffffff91602435838116810361049f578152604435838116810361049f57602082015265ffffffffffff606435818116810361032a5788830152608435908116810361049f576060820152815260a435938285168503610bda576020820194855260c4359087830182815260e43567ffffffffffffffff811161032657610cfe90369084016115c1565b929093804211610d88575050918591610d786102f6999a610d7e95610d238851611fbe565b90898c511690519083519260208401947ff3841cd1ff0085026a6327b620b67997ce40f282c88a8e905a7a5626e310f3d086528401526060830152608082015260808152610d70816113ff565b519020611bd9565b916120c7565b519251169161199d565b602492508a51917fcd21db4f000000000000000000000000000000000000000000000000000000008352820152fd5b5091346103365760607ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc93818536011261033257610df36114a0565b9260249081359267ffffffffffffffff9788851161032a578590853603011261049f578051978589018981108282111761104a578252848301358181116103265785019036602383011215610326578382013591610e50836115ef565b90610e5d85519283611437565b838252602093878584019160071b83010191368311611046578801905b828210610fe9575050508a526044610e93868801611509565b96838c01978852013594838b0191868352604435908111610fe557610ebb90369087016115c1565b959096804211610fba575050508998995151610ed681611ebb565b908b5b818110610f9757505092889492610d7892610f6497958351610f02816103f98682018095611f66565b5190209073ffffffffffffffffffffffffffffffffffffffff9a8b8b51169151928551948501957faf1b0d30d2cab0380e68f0689007e3254993c596f2fdd0aaa7f4d04f794408638752850152830152608082015260808152610d70816113ff565b51169082515192845b848110610f78578580f35b80610f918585610f8b600195875161175e565b5161199d565b01610f6d565b80610311610fac8e9f9e93610fb2945161175e565b51611fbe565b9b9a9b610ed9565b8551917fcd21db4f000000000000000000000000000000000000000000000000000000008352820152fd5b8a80fd5b6080823603126110465785608091885161100281611398565b61100b85611509565b8152611018838601611509565b838201526110278a8601611607565b8a8201528d611037818701611607565b90820152815201910190610e7a565b8c80fd5b84896041867f4e487b7100000000000000000000000000000000000000000000000000000000835252fd5b5082346105bf576101407ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126105bf576110b03661152a565b91807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7c360112610332576110e2611478565b67ffffffffffffffff93906101043585811161049f5761110590369086016115c1565b90936101243596871161032a57611125610bd1966102f6983691016115c1565b969095825190611134826113ff565b606482527f5065726d69745769746e6573735472616e7366657246726f6d28546f6b656e5060208301527f65726d697373696f6e73207065726d69747465642c6164647265737320737065848301527f6e6465722c75696e74323536206e6f6e63652c75696e7432353620646561646c60608301527f696e652c0000000000000000000000000000000000000000000000000000000060808301528351948591816111e3602085018096611f93565b918237018b8152039361121c7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe095868101835282611437565b5190209261122a8651612054565b6020878101518589015195519182019687526040820192909252336060820152608081019190915260a081019390935260e43560c08401528260e081016102e1565b5082346105bf576020807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261033257813567ffffffffffffffff92838211610bda5736602383011215610bda5781013592831161032e576024906007368386831b8401011161049f57865b8581106112e5578780f35b80821b83019060807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc83360301126103265761139288876001946060835161132c81611398565b611368608461133c8d8601611509565b9485845261134c60448201611509565b809785015261135d60648201611509565b809885015201611509565b918291015273ffffffffffffffffffffffffffffffffffffffff80808093169516931691166117a1565b016112da565b6080810190811067ffffffffffffffff8211176113b457604052565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6060810190811067ffffffffffffffff8211176113b457604052565b60a0810190811067ffffffffffffffff8211176113b457604052565b60c0810190811067ffffffffffffffff8211176113b457604052565b90601f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0910116810190811067ffffffffffffffff8211176113b457604052565b60c4359073ffffffffffffffffffffffffffffffffffffffff8216820361149b57565b600080fd5b6004359073ffffffffffffffffffffffffffffffffffffffff8216820361149b57565b6024359073ffffffffffffffffffffffffffffffffffffffff8216820361149b57565b6044359073ffffffffffffffffffffffffffffffffffffffff8216820361149b57565b359073ffffffffffffffffffffffffffffffffffffffff8216820361149b57565b7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc01906080821261149b576040805190611563826113e3565b8082941261149b57805181810181811067ffffffffffffffff8211176113b457825260043573ffffffffffffffffffffffffffffffffffffffff8116810361149b578152602435602082015282526044356020830152606435910152565b9181601f8401121561149b5782359167ffffffffffffffff831161149b576020838186019501011161149b57565b67ffffffffffffffff81116113b45760051b60200190565b359065ffffffffffff8216820361149b57565b9181601f8401121561149b5782359167ffffffffffffffff831161149b576020808501948460061b01011161149b57565b91909160608184031261149b576040805191611666836113e3565b8294813567ffffffffffffffff9081811161149b57830182601f8201121561149b578035611693816115ef565b926116a087519485611437565b818452602094858086019360061b8501019381851161149b579086899897969594939201925b8484106116e3575050505050855280820135908501520135910152565b90919293949596978483031261149b578851908982019082821085831117611730578a928992845261171487611509565b81528287013583820152815201930191908897969594936116c6565b602460007f4e487b710000000000000000000000000000000000000000000000000000000081526041600452fd5b80518210156117725760209160051b010190565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b92919273ffffffffffffffffffffffffffffffffffffffff604060008284168152600160205282828220961695868252602052818120338252602052209485549565ffffffffffff8760a01c16804211611884575082871696838803611812575b5050611810955016926118b5565b565b878484161160001461184f57602488604051907ff96fb0710000000000000000000000000000000000000000000000000000000082526004820152fd5b7fffffffffffffffffffffffff000000000000000000000000000000000000000084846118109a031691161790553880611802565b602490604051907fd81b2f2e0000000000000000000000000000000000000000000000000000000082526004820152fd5b9060006064926020958295604051947f23b872dd0000000000000000000000000000000000000000000000000000000086526004860152602485015260448401525af13d15601f3d116001600051141617161561190e57565b60646040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601460248201527f5452414e534645525f46524f4d5f4641494c45440000000000000000000000006044820152fd5b91908110156117725760061b0190565b3573ffffffffffffffffffffffffffffffffffffffff8116810361149b5790565b9065ffffffffffff908160608401511673ffffffffffffffffffffffffffffffffffffffff908185511694826020820151169280866040809401511695169560009187835260016020528383208984526020528383209916988983526020528282209184835460d01c03611af5579185611ace94927fc6a377bfc4eb120024a8ac08eef205be16b817020812c73223e81d1bdb9708ec98979694508715600014611ad35779ffffffffffff00000000000000000000000000000000000000009042165b60a01b167fffffffffffff00000000000000000000000000000000000000000000000000006001860160d01b1617179055519384938491604091949373ffffffffffffffffffffffffffffffffffffffff606085019616845265ffffffffffff809216602085015216910152565b0390a4565b5079ffffffffffff000000000000000000000000000000000000000087611a60565b600484517f756688fe000000000000000000000000000000000000000000000000000000008152fd5b467f000000000000000000000000000000000000000000000000000000000000000003611b69577f000000000000000000000000000000000000000000000000000000000000000090565b60405160208101907f8cad95687ba82c2ce50e74f7b754645e5117c3a5bec8151c0726d5857980a86682527f9ac997416e8ff9d2ff6bebeb7149f65cdae5e32e2b90440b566bb3044041d36a604082015246606082015230608082015260808152611bd3816113ff565b51902090565b611be1611b1e565b906040519060208201927f190100000000000000000000000000000000000000000000000000000000000084526022830152604282015260428152611bd381611398565b9192909360a435936040840151804211611cc65750602084510151808611611c955750918591610d78611c6594611c60602088015186611e47565b611bd9565b73ffffffffffffffffffffffffffffffffffffffff809151511692608435918216820361149b57611810936118b5565b602490604051907f3728b83d0000000000000000000000000000000000000000000000000000000082526004820152fd5b602490604051907fcd21db4f0000000000000000000000000000000000000000000000000000000082526004820152fd5b959093958051519560409283830151804211611e175750848803611dee57611d2e918691610d7860209b611c608d88015186611e47565b60005b868110611d42575050505050505050565b611d4d81835161175e565b5188611d5a83878a61196c565b01359089810151808311611dbe575091818888886001968596611d84575b50505050505001611d31565b611db395611dad9273ffffffffffffffffffffffffffffffffffffffff6105159351169561196c565b916118b5565b803888888883611d78565b6024908651907f3728b83d0000000000000000000000000000000000000000000000000000000082526004820152fd5b600484517fff633a38000000000000000000000000000000000000000000000000000000008152fd5b6024908551907fcd21db4f0000000000000000000000000000000000000000000000000000000082526004820152fd5b9073ffffffffffffffffffffffffffffffffffffffff600160ff83161b9216600052600060205260406000209060081c6000526020526040600020818154188091551615611e9157565b60046040517f756688fe000000000000000000000000000000000000000000000000000000008152fd5b90611ec5826115ef565b611ed26040519182611437565b8281527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0611f0082946115ef565b0190602036910137565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8114611f375760010190565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b805160208092019160005b828110611f7f575050505090565b835185529381019392810192600101611f71565b9081519160005b838110611fab575050016000815290565b8060208092840101518185015201611f9a565b60405160208101917f65626cad6cb96493bf6f5ebea28756c966f023ab9e8a83a7101849d5573b3678835273ffffffffffffffffffffffffffffffffffffffff8082511660408401526020820151166060830152606065ffffffffffff9182604082015116608085015201511660a082015260a0815260c0810181811067ffffffffffffffff8211176113b45760405251902090565b6040516020808201927f618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1845273ffffffffffffffffffffffffffffffffffffffff81511660408401520151606082015260608152611bd381611398565b919082604091031261149b576020823592013590565b6000843b61222e5750604182036121ac576120e4828201826120b1565b939092604010156117725760209360009360ff6040608095013560f81c5b60405194855216868401526040830152606082015282805260015afa156121a05773ffffffffffffffffffffffffffffffffffffffff806000511691821561217657160361214c57565b60046040517f815e1d64000000000000000000000000000000000000000000000000000000008152fd5b60046040517f8baa579f000000000000000000000000000000000000000000000000000000008152fd5b6040513d6000823e3d90fd5b60408203612204576121c0918101906120b1565b91601b7f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff84169360ff1c019060ff8211611f375760209360009360ff608094612102565b60046040517f4be6321b000000000000000000000000000000000000000000000000000000008152fd5b929391601f928173ffffffffffffffffffffffffffffffffffffffff60646020957fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0604051988997889687947f1626ba7e000000000000000000000000000000000000000000000000000000009e8f8752600487015260406024870152816044870152868601378b85828601015201168101030192165afa9081156123a857829161232a575b507fffffffff000000000000000000000000000000000000000000000000000000009150160361230057565b60046040517fb0669cbc000000000000000000000000000000000000000000000000000000008152fd5b90506020813d82116123a0575b8161234460209383611437565b810103126103365751907fffffffff0000000000000000000000000000000000000000000000000000000082168203610a9a57507fffffffff0000000000000000000000000000000000000000000000000000000090386122d4565b3d9150612337565b6040513d84823e3d90fdfea164736f6c6343000811000a';

        (bool ok,) = permit2Deployer.call(permit2CreationCalldata);
        require(ok && PERMIT2.code.length != 0, 'permit2 deployment failed');
    }

    /* --------------------------------------------------------------------- */
    /*                               Helpers                                 */
    /* --------------------------------------------------------------------- */

    function _composeNonceUint(address a, uint256 nonce) internal pure returns (uint256) {
        // Nonce structure: command (8 bits) | address (160 bits) | nonce (88 bits)
        // ON_CHAIN_NONCE = 0x01
        return (uint256(0x01) << 248) | (uint256(uint160(a)) << 88) | nonce;
    }

    /* --------------------------------------------------------------------- */
    /*                        Permit2 Helper Functions                       */
    /* --------------------------------------------------------------------- */

    function _getLockTag() internal view returns (bytes12) {
        return _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes);
    }

    function _getPermit2DomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(PERMIT2_DOMAIN_SEPARATOR_TYPEHASH, keccak256(bytes('Permit2')), block.chainid, PERMIT2)
        );
    }

    function _createTokenPermissions(address token, uint256 amount)
        internal
        pure
        returns (ISignatureTransfer.TokenPermissions[] memory)
    {
        ISignatureTransfer.TokenPermissions[] memory permitted = new ISignatureTransfer.TokenPermissions[](1);
        permitted[0] = ISignatureTransfer.TokenPermissions({token: token, amount: amount});
        return permitted;
    }

    function _createTokenPermissions2(address token1, uint256 amount1, address token2, uint256 amount2)
        internal
        pure
        returns (ISignatureTransfer.TokenPermissions[] memory)
    {
        ISignatureTransfer.TokenPermissions[] memory permitted = new ISignatureTransfer.TokenPermissions[](2);
        permitted[0] = ISignatureTransfer.TokenPermissions({token: token1, amount: amount1});
        permitted[1] = ISignatureTransfer.TokenPermissions({token: token2, amount: amount2});
        return permitted;
    }

    function _createDepositDetails(uint256 nonce, uint256 deadline, bytes12 lockTag)
        internal
        pure
        returns (DepositDetails memory)
    {
        return DepositDetails({nonce: nonce, deadline: deadline, lockTag: lockTag});
    }

    function _hashTokenPermissions(ISignatureTransfer.TokenPermissions[] memory permitted)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory hashes = new bytes32[](permitted.length);
        for (uint256 i = 0; i < permitted.length; i++) {
            hashes[i] = keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, permitted[i].token, permitted[i].amount));
        }
        return keccak256(abi.encodePacked(hashes));
    }

    /// @dev Computes the Lock commitment hash with proper struct encoding
    function _computeCommitmentHash(uint256 id, uint256 amount) internal pure returns (bytes32) {
        bytes32 lockTypehash = keccak256('Lock(bytes12 lockTag,address token,uint256 amount)');
        bytes12 lockTag = bytes12(bytes32(id));
        address token = address(uint160(id));
        return keccak256(abi.encode(lockTypehash, lockTag, token, amount));
    }

    /// @dev Creates a permit2 nonce with the correct command byte and sponsor address
    function _createPermit2Nonce(address sponsor, uint88 freeNonce) internal pure returns (uint256) {
        // First byte: PERMIT2_NONCE (0x03)
        // Next 20 bytes: sponsor address
        // Last 11 bytes: free nonce
        return uint256(0x03) << 248 | uint256(uint160(sponsor)) << 88 | uint256(freeNonce);
    }

    function _createPermit2Signature(
        ISignatureTransfer.TokenPermissions[] memory permitted,
        DepositDetails memory details,
        bytes32 claimHash,
        uint256 signerPk
    ) internal view returns (bytes memory) {
        bytes12 lockTag = details.lockTag;

        // Check if first token is native
        bool hasNative = permitted.length > 0 && permitted[0].token == address(0);

        // Create ids array - includes ALL tokens (including native)
        uint256[] memory ids = new uint256[](permitted.length);
        for (uint256 i = 0; i < permitted.length; i++) {
            ids[i] = AllocatorLib.toId(lockTag, permitted[i].token);
        }
        bytes32 idsHash = keccak256(abi.encodePacked(ids));

        // Create activation hash using the exact same typehash TheCompact uses
        // The activator is the allocator (msg.sender to TheCompact)
        bytes32 activationHash =
            keccak256(abi.encode(BATCH_COMPACT_BATCH_ACTIVATION_TYPEHASH, address(allocator), idsHash, claimHash));

        // Create permit batch hash - tokenPermissionsHash only includes ERC20 tokens (not native)
        ISignatureTransfer.TokenPermissions[] memory erc20Permitted;
        if (hasNative) {
            erc20Permitted = new ISignatureTransfer.TokenPermissions[](permitted.length - 1);
            for (uint256 i = 0; i < erc20Permitted.length; i++) {
                erc20Permitted[i] = permitted[i + 1];
            }
        } else {
            erc20Permitted = permitted;
        }
        bytes32 tokenPermissionsHash = _hashTokenPermissions(erc20Permitted);
        bytes32 permitBatchHash = keccak256(
            abi.encode(
                PERMIT_BATCH_WITNESS_TYPEHASH,
                tokenPermissionsHash,
                address(compact),
                details.nonce,
                details.deadline,
                activationHash
            )
        );

        // Create digest
        bytes32 domainSeparator = _getPermit2DomainSeparator();
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), domainSeparator, permitBatchHash));

        // Sign
        (bytes32 r, bytes32 vs) = vm.signCompact(signerPk, digest);
        return abi.encodePacked(r, vs);
    }

    function _commitmentsHash(Lock[] memory commitments) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; i++) {
            hashes[i] = keccak256(
                abi.encode(LOCK_TYPEHASH, commitments[i].lockTag, commitments[i].token, commitments[i].amount)
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function _makeLock(address token, uint256 amount) internal view returns (Lock memory l) {
        bytes12 lockTag = _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes);
        l = Lock({lockTag: lockTag, token: token, amount: amount});
    }

    function _createClaimHash(
        address sponsor,
        address arbiter_,
        uint256 nonce,
        uint256 expiration,
        Lock[] memory commitments,
        bytes32 witness
    ) internal pure returns (bytes32) {
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        if (witness == bytes32(0)) {
            return keccak256(abi.encode(BATCH_COMPACT_TYPEHASH, arbiter_, sponsor, nonce, expiration, commitmentsHash));
        } else {
            return keccak256(
                abi.encode(
                    BATCH_COMPACT_TYPEHASH_WITH_WITNESS, arbiter_, sponsor, nonce, expiration, commitmentsHash, witness
                )
            );
        }
    }

    /* --------------------------------------------------------------------- */
    /*                     Helpers for Reentrancy Tests                     */
    /* --------------------------------------------------------------------- */

    /**
     * @notice Creates a helper function for testing native token reentrancy.
     * @dev Flow using ERC1271 + OnChainAllocator:
     *      1. MaliciousRecipient deposits native tokens using OnChainAllocator's lockTag
     *      2. MaliciousRecipient calls allocate() to register with OnChainAllocator
     *      3. Returns id, claimHash, and nonce
     *      4. The claim uses OnChainAllocator for validation (checks stored claimHash)
     *      5. During withdrawal, receive() tries to call allocate() again → should fail
     */
    function _setupNativeTokenReentrancyTest() internal returns (uint256 id, bytes32 claimHash, uint256 nonce) {
        // MaliciousRecipient deposits native tokens using OnChainAllocator's lockTag
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({
            lockTag: _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes),
            token: address(0), // native token
            amount: defaultAmount
        });

        bytes12 lockTag = commitments[0].lockTag;
        deal(address(maliciousRecipient), defaultAmount);
        vm.prank(address(maliciousRecipient));
        id = compact.depositNative{value: defaultAmount}(lockTag, address(maliciousRecipient));

        // MaliciousRecipient calls allocate() to store claimHash in OnChainAllocator
        vm.prank(address(maliciousRecipient));
        (claimHash, nonce) = allocator.allocate(
            commitments, address(maliciousRecipient), defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    /**
     * @notice Creates a withdrawal BatchClaim struct for maliciousRecipient.
     * @dev Creates a simple withdrawal batch claim that uses OnChainAllocator:
     *      - Empty sponsorSignature triggers ERC1271 validation
     *      - MaliciousRecipient.isValidSignature() always returns success (0x1626ba7e)
     *      - lockTag = 0 in portions indicates withdrawal (native tokens sent)
     *      - allocatorData is empty (OnChainAllocator validates via stored claimHash)
     *      - sponsor = maliciousRecipient
     *      - arbiter = maliciousRecipient (when sponsor calls, arbiter must match)
     */
    function _createClaimForMaliciousRecipient(uint256 id, uint256 nonce, uint256 amount)
        internal
        view
        returns (BatchClaim memory)
    {
        // Create withdrawal portion (lockTag = 0 means withdrawal to native tokens)
        uint256 claimant = uint256(bytes32(abi.encodePacked(bytes12(0), address(maliciousRecipient))));
        Component[] memory portions = new Component[](1);
        portions[0] = Component({claimant: claimant, amount: amount});

        // Create BatchClaimComponent for this token
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        claims[0] = BatchClaimComponent({id: id, allocatedAmount: amount, portions: portions});

        return BatchClaim({
            allocatorData: bytes(''), // Empty - OnChainAllocator validates via stored claimHash
            sponsorSignature: bytes(''), // Empty - triggers ERC1271 validation
            sponsor: address(maliciousRecipient), // MaliciousRecipient is the sponsor
            nonce: nonce,
            expires: defaultExpiration,
            witness: bytes32(0),
            witnessTypestring: '',
            claims: claims
        });
    }

    /* --------------------------------------------------------------------- */
    /*                               allocate()                              */
    /* --------------------------------------------------------------------- */

    function test_allocate_revert_InvalidCommitments() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidCommitments.selector));
        allocator.allocate(new Lock[](0), arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_allocate_revert_InvalidExpiration() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // Deposit native token to Compact first so allocation is backed
        bytes12 lockTag = commitments[0].lockTag;
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(lockTag, user);

        uint256 expiration = vm.getBlockTimestamp() + 600; // 10 min reset period

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidExpiration.selector, expiration, expiration));
        allocator.allocate(commitments, arbiter, uint32(expiration), BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_allocate_revert_ForceWithdrawalAvailable() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // Deposit native token to Compact first so allocation is backed
        bytes12 lockTag = commitments[0].lockTag;
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(lockTag, user);

        // Enable forced withdrawal
        vm.prank(user);
        (uint256 withdrawableAt) = compact.enableForcedWithdrawal(
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0))
        );

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.ForceWithdrawalAvailable.selector, withdrawableAt, withdrawableAt)
        );
        allocator.allocate(commitments, arbiter, uint32(withdrawableAt), BATCH_COMPACT_TYPEHASH, bytes32(0));

        vm.prank(user);
        allocator.allocate(commitments, arbiter, uint32(withdrawableAt - 1), BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_allocate_revert_InvalidAmount() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), uint256(type(uint224).max) + 1);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, commitments[0].amount));
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_allocate_revert_InsufficientBalance() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // No deposit made for native token – balance is zero, should revert.
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IOnChainAllocator.InsufficientBalance.selector,
                user,
                _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0)),
                0,
                defaultAmount
            )
        );
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_allocate_revert_InvalidAllocator() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        commitments[0].lockTag = bytes12(commitments[0].lockTag & bytes12(0x110000000000000000000000));

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidAllocator.selector, 0, allocator.ALLOCATOR_ID())
        );
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_allocate_success_nativeToken() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // Deposit native token to Compact first so allocation is backed
        bytes12 lockTag = commitments[0].lockTag;
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(lockTag, user);

        vm.prank(user);
        (bytes32 claimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.snapshotGasLastCall('allocate_native');

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(nonce, defaultNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_allocate_success_erc20() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        // Deposit ERC20 into Compact so allocation is backed
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);
        vm.prank(user);
        compact.depositERC20(address(usdc), commitments[0].lockTag, defaultAmount, user);

        vm.prank(user);
        (bytes32 claimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.snapshotGasLastCall('allocate_erc20');

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(nonce, defaultNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_allocate_success_erc20_multipleAllocations() public {
        uint256 amount = defaultAmount / 2;
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), amount);

        // Deposit ERC20 into Compact so allocation is backed
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);
        vm.prank(user);
        compact.depositERC20(address(usdc), commitments[0].lockTag, defaultAmount, user);

        vm.prank(user);
        (bytes32 claimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.snapshotGasLastCall('allocate_erc20');

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = amount;

        assertEq(nonce, defaultNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        vm.prank(user);
        (claimHash, nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration + 10, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.snapshotGasLastCall('allocate_second_erc20');

        assertEq(nonce, defaultNonce + 1);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration + 10, idsAndAmounts, '')
        );

        // expire the first allocation and allocate again
        vm.warp(defaultExpiration + 1);
        vm.prank(user);
        (claimHash, nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration + 10, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.snapshotGasLastCall('allocate_and_delete_expired_allocation');

        assertEq(nonce, defaultNonce + 2);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration + 10, idsAndAmounts, '')
        );
    }

    function test_allocate_fuzz(uint128 depositAmount, uint128 firstAmount, uint128 secondAmount, bytes32 witness)
        public
    {
        vm.assume(depositAmount > 0);
        vm.assume(firstAmount <= depositAmount);

        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), firstAmount);

        // Deposit ERC20 into Compact so allocation is backed
        vm.startPrank(user);
        usdc.mint(user, depositAmount);
        usdc.approve(address(compact), depositAmount);
        compact.depositERC20(address(usdc), commitments[0].lockTag, depositAmount, user);
        vm.stopPrank();

        uint256 expectedNonce = defaultNonce;
        bytes32 claimHash = _createClaimHash(user, arbiter, expectedNonce, defaultExpiration, commitments, witness);

        // first allocation

        bytes32 typehash = witness == bytes32(0) ? BATCH_COMPACT_TYPEHASH : BATCH_COMPACT_TYPEHASH_WITH_WITNESS;

        vm.prank(user);
        vm.expectEmit(true, true, true, true);
        emit IOnChainAllocation.Allocated(user, commitments, expectedNonce, defaultExpiration, claimHash);
        (bytes32 returnedClaimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, typehash, witness);

        assertEq(returnedClaimHash, claimHash);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = firstAmount;

        assertEq(nonce, expectedNonce, 'nonce 1');
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        // second allocation
        commitments[0].amount = secondAmount;

        vm.prank(user);
        if (uint256(secondAmount) + uint256(firstAmount) > depositAmount) {
            // expect a revert of the second allocation
            vm.expectRevert(
                abi.encodeWithSelector(
                    IOnChainAllocator.InsufficientBalance.selector,
                    user,
                    _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc)),
                    depositAmount - firstAmount,
                    secondAmount
                )
            );
        } else {
            // expect a successful second allocation
            expectedNonce = defaultNonce + 1;
            claimHash = _createClaimHash(user, arbiter, expectedNonce, defaultExpiration, commitments, witness);
            vm.expectEmit(true, true, true, true);
            emit IOnChainAllocation.Allocated(user, commitments, expectedNonce, defaultExpiration, claimHash);
        }
        (claimHash, nonce) = allocator.allocate(commitments, arbiter, defaultExpiration, typehash, witness);

        if (uint256(secondAmount) + uint256(firstAmount) <= depositAmount) {
            // Check the allocations
            idsAndAmounts[0][1] = secondAmount;

            assertEq(nonce, expectedNonce, 'nonce 1');
            assertTrue(
                allocator.isClaimAuthorized(
                    claimHash, arbiter, user, defaultNonce, /*nonce*/ defaultExpiration, idsAndAmounts, ''
                )
            );
            assertTrue(
                allocator.isClaimAuthorized(
                    claimHash, arbiter, user, defaultNonce + 1, /*nonce*/ defaultExpiration, idsAndAmounts, ''
                )
            );

            uint256 amountToAttest = depositAmount - (uint256(secondAmount) + uint256(firstAmount));

            assertEq(
                allocator.attest(address(this), user, address(this), idsAndAmounts[0][0], amountToAttest),
                IAllocator.attest.selector
            );
            vm.expectRevert(
                abi.encodeWithSelector(
                    IOnChainAllocator.InsufficientBalance.selector,
                    user,
                    idsAndAmounts[0][0],
                    amountToAttest,
                    amountToAttest + 1
                )
            );
            allocator.attest(address(this), user, address(this), idsAndAmounts[0][0], amountToAttest + 1);
        } else if (secondAmount <= depositAmount) {
            // Second allocation should be possible after the first one is expired
            vm.warp(defaultExpiration + 1);
            uint32 expiration = defaultExpiration + 100;
            expectedNonce = defaultNonce + 1;

            vm.prank(user);
            (claimHash, nonce) = allocator.allocate(commitments, arbiter, expiration, typehash, witness);
            assertEq(nonce, expectedNonce, 'nonce 2');
            assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, expiration, idsAndAmounts, ''));
        }
    }

    /* --------------------------------------------------------------------- */
    /*                           allocateFor()                               */
    /* --------------------------------------------------------------------- */
    function test_allocateFor_revert_InvalidExpiration(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        vm.warp(defaultExpiration);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidExpiration.selector, defaultExpiration, block.timestamp)
        );
        allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, '');
    }

    function test_allocateFor_revert_InvalidSignature() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        (address attacker, uint256 attackerPK) = makeAddrAndKey('attacker');

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);

        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash)
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPK, digest);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidSignature.selector, attacker, user));
        allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, badSig);
    }

    function test_allocateFor_revert_InvalidSignature_invalidSignatureLength(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);

        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash)
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPK, digest);
        bytes memory sig = abi.encode(r, s, v); // wrong length because not packed: 96 bytes instead of 65 bytes

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidSignature.selector, address(0), user));
        allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, sig);
    }

    function test_allocateFor_revert_oldSignatureAfterFork(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash)
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        uint256 snap = vm.snapshot();
        assertEq(block.chainid, 31_337);

        vm.prank(relayer);
        (bytes32 returnedHash, uint256 nonce) =
            allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, sig);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(returnedHash, claimHash);
        assertEq(nonce, expectedNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        vm.revertTo(snap);
        vm.chainId(1);
        assertEq(block.chainid, 1);

        // After chain fork, the domain separator changes, so the signature will recover
        // to a different address (not the user). We compute the wrong recovered address
        // by using the new chain's domain separator with the old signature.
        bytes32 newDigest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        address wrongSigner = ecrecover(newDigest, v, r, s);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidSignature.selector, wrongSigner, user));
        allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, sig);
    }

    function test_allocateFor_success_withCompactSignature(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);

        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash)
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        (bytes32 r, bytes32 vs) = vm.signCompact(userPK, digest);
        bytes memory sig = abi.encodePacked(r, vs);

        vm.prank(relayer);
        (bytes32 returnedHash, uint256 nonce) =
            allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, sig);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(returnedHash, claimHash);
        assertEq(nonce, expectedNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_allocateFor_success_withSignature(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash)
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(relayer);
        (bytes32 returnedHash, uint256 nonce) =
            allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, sig);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(returnedHash, claimHash);
        assertEq(nonce, expectedNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_allocateFor_success_withSignature_multipleCommitments(address relayer) public {
        Lock[] memory commitments = new Lock[](2);
        commitments[0] = _makeLock(address(0), defaultAmount);
        commitments[1] = _makeLock(address(usdc), defaultAmount);
        vm.startPrank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compact), defaultAmount);
        compact.depositERC20(address(usdc), commitments[1].lockTag, defaultAmount, user);
        vm.stopPrank();

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash)
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(relayer);
        (bytes32 returnedHash, uint256 nonce) =
            allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, sig);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(returnedHash, claimHash);
        assertEq(nonce, expectedNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_allocateFor_success_withWitness(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);
        bytes32 witness = bytes32(keccak256('witness'));
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash, witness
            )
        );
        bytes memory sig;
        {
            bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPK, digest);
            sig = abi.encodePacked(r, s, v);
        }
        vm.prank(relayer);
        (bytes32 returnedHash, uint256 nonce) =
            allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, witness, sig);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(returnedHash, claimHash);
        assertEq(nonce, expectedNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        assertEq(allocator.nonces(user), 1);
    }

    function test_allocateFor_revert_InvalidRegistration(address relayer) public {
        // Build commitments with native token deposit backing
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // Nonce that allocateFor will use
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);

        // Compute claimHash that allocateFor will create internally
        bytes32 claimHash = _createClaimHash(user, arbiter, expectedNonce, defaultExpiration, commitments, bytes32(0));

        // Expect InvalidRegistration revert because claimHash is NOT registered on The Compact
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocation.InvalidRegistration.selector, user, claimHash));
        allocator.allocateFor(
            user,
            commitments,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0),
            '' // empty signature triggers registration check
        );
    }

    function test_allocateFor_success_noSignature() public {
        address relayer = makeAddr('relayer');
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // Determine nonce the allocator will use
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);

        // Pre-compute claimHash that `allocateFor` will produce
        bytes32 claimHash = _createClaimHash(user, arbiter, expectedNonce, defaultExpiration, commitments, bytes32(0));

        // Prepare ids & amounts for native token deposit + registration
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        // Prepare claimHashes+typehashes array for registration
        bytes32[2][] memory claimHashesAndTypehashes = new bytes32[2][](1);
        claimHashesAndTypehashes[0][0] = claimHash;
        claimHashesAndTypehashes[0][1] = BATCH_COMPACT_TYPEHASH;

        // User deposits native token & registers the compact directly on TheCompact
        vm.prank(user);
        compact.batchDepositAndRegisterMultiple{value: defaultAmount}(idsAndAmounts, claimHashesAndTypehashes);

        // Relayer submits allocateFor WITHOUT any signature (length == 0)
        vm.prank(relayer);
        (bytes32 returnedHash, uint256 nonce) = allocator.allocateFor(
            user,
            commitments,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0),
            '' // empty signature triggers the "registered" code path
        );
        vm.snapshotGasLastCall('allocateFor_success_withRegistration');

        // Assertions
        assertEq(returnedHash, claimHash);
        assertEq(nonce, expectedNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    /* --------------------------------------------------------------------- */
    /*                           isClaimAuthorized()                         */
    /* --------------------------------------------------------------------- */

    function test_isClaimAuthorized_false_notAuthorized() public view {
        assertFalse(allocator.isClaimAuthorized(bytes32(0), arbiter, user, 0, 0, new uint256[2][](0), ''));
    }

    function test_isClaimAuthorized_false_expired() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        vm.prank(user);
        (bytes32 claimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        vm.prank(user);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        vm.warp(defaultExpiration + 1);
        vm.prank(user);
        assertFalse(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_isClaimAuthorized_success() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        vm.prank(user);
        (bytes32 claimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        vm.prank(user);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        vm.warp(defaultExpiration);
        vm.prank(user);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    /* --------------------------------------------------------------------- */
    /*                         authorizeClaim()                              */
    /* --------------------------------------------------------------------- */

    function test_authorizeClaim_invalidCaller() public {
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidCaller.selector, address(this), address(compact))
        );
        allocator.authorizeClaim(bytes32(0), arbiter, user, 0, 0, new uint256[2][](0), '');
    }

    function test_authorizeClaim_success() public {
        // register claim via allocate()
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // back with native deposit
        bytes12 lt = commitments[0].lockTag;
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(lt, user);
        vm.prank(user);
        (bytes32 claimHash,) =
            allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        uint256 idNat = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][0] = idNat;
        idsAndAmounts[0][1] = defaultAmount;

        // call from Compact contract address
        vm.prank(address(compact));
        bytes4 sel = allocator.authorizeClaim(claimHash, arbiter, user, 1, defaultExpiration, idsAndAmounts, '');
        assertEq(sel, IAllocator.authorizeClaim.selector);

        // check deletion of the allocation
        vm.prank(address(compact));
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidClaim.selector, claimHash));
        allocator.authorizeClaim(claimHash, arbiter, user, 1, defaultExpiration, idsAndAmounts, '');
    }

    function test_authorizeClaim_deletesMiddleOfMultipleAllocations_correctly() public {
        // Prepare a large ERC20 deposit so three allocations can be made for the same id.
        uint256 amount1 = 1 ether;
        uint256 amount2 = 2 ether;
        uint256 amount3 = 3 ether;
        uint256 total = amount1 + amount2 + amount3;

        // Deposit ERC20 into Compact for the user
        bytes12 lockTag = _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes);
        vm.startPrank(user);
        usdc.mint(user, total);
        usdc.approve(address(compact), total);
        compact.depositERC20(address(usdc), lockTag, total, user);
        vm.stopPrank();

        // Make three allocations for the same id with increasing expirations
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: amount1});
        bytes32 claimHash1;
        {
            vm.prank(user);
            (claimHash1,) = allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        }

        bytes32 claimHash2;
        {
            commitments[0].amount = amount2;
            vm.prank(user);
            (claimHash2,) = allocator.allocate(commitments, arbiter, defaultExpiration + 10, BATCH_COMPACT_TYPEHASH, '');
        }

        bytes32 claimHash3;
        {
            commitments[0].amount = amount3;
            vm.prank(user);
            (claimHash3,) = allocator.allocate(commitments, arbiter, defaultExpiration + 20, BATCH_COMPACT_TYPEHASH, '');
        }

        // idsAndAmounts used by authorizeClaim (amount is not used for verification but keep it consistent)
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = amount1;

        // 1) Delete the MIDDLE allocation first (claimHash2). This exercises swap-and-pop correctness.
        vm.prank(address(compact));
        bytes4 sel = allocator.authorizeClaim(claimHash2, arbiter, user, 0, defaultExpiration, idsAndAmounts, '');
        assertEq(sel, IAllocator.authorizeClaim.selector);

        // 2) The other allocations must still be present and independently deletable.
        vm.prank(address(compact));
        sel = allocator.authorizeClaim(claimHash3, arbiter, user, 0, defaultExpiration, idsAndAmounts, '');
        assertEq(sel, IAllocator.authorizeClaim.selector);

        vm.prank(address(compact));
        sel = allocator.authorizeClaim(claimHash1, arbiter, user, 0, defaultExpiration, idsAndAmounts, '');
        assertEq(sel, IAllocator.authorizeClaim.selector);

        // 3) All allocations are deleted now; reusing any claim should revert.
        vm.prank(address(compact));
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidClaim.selector, claimHash1));
        allocator.authorizeClaim(claimHash1, arbiter, user, 0, defaultExpiration, idsAndAmounts, '');
    }

    /* --------------------------------------------------------------------- */
    /*                                 attest                                */
    /* --------------------------------------------------------------------- */

    function test_attest_revert_InsufficientBalance() public {
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, user, id, 0, defaultAmount)
        );
        allocator.attest(address(0), user, address(0), id, defaultAmount);
    }

    function test_attest_revert_InsufficientBalance_previousAllocation() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        vm.prank(user);
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, user, id, 0, 1));
        allocator.attest(address(this), user, address(this), id, 1);
    }

    function test_attest_success_previousAllocation() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount - 1);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        vm.prank(user);
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        vm.prank(user);
        vm.assertEq(allocator.attest(address(this), user, address(this), id, 1), allocator.attest.selector);
    }

    function test_attest_success() public {
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        // deposit id to Compact for user
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(bytes12(bytes32(id)), user);

        vm.prank(user);
        bytes4 sel = allocator.attest(address(0), user, address(0), id, defaultAmount);
        assertEq(sel, allocator.attest.selector);
    }

    /* --------------------------------------------------------------------- */
    /*                          allocateAndRegister()                        */
    /* --------------------------------------------------------------------- */

    function test_allocateAndRegister_revert_InvalidExpiration() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        // Fund allocator with tokens
        usdc.mint(address(allocator), defaultAmount);

        uint256 expiration = block.timestamp + 600;
        vm.prank(caller);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidExpiration.selector, expiration, block.timestamp + 600)
        );
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, uint32(expiration), BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    /* --------------------------------------------------------------------- */
    /*                   prepareAllocation / executeAllocation               */
    /* --------------------------------------------------------------------- */

    function _idsAndAmountsFor(address token, uint256 amount)
        internal
        view
        returns (uint256[2][] memory idsAndAmounts)
    {
        idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), token);
        idsAndAmounts[0][1] = amount;
    }

    function _idsAndAmountsFor2(address tokenA, uint256 amountA, address tokenB, uint256 amountB)
        internal
        view
        returns (uint256[2][] memory idsAndAmounts)
    {
        idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), tokenA);
        idsAndAmounts[0][1] = amountA;
        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), tokenB);
        idsAndAmounts[1][1] = amountB;
    }

    function test_prepareAllocation_revert_InvalidAllocatorId() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(this), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        uint96 allocatorId = _toAllocatorId(address(this));

        vm.expectRevert(
            abi.encodeWithSelector(AllocatorLib.InvalidAllocatorId.selector, allocatorId, allocator.ALLOCATOR_ID())
        );
        allocator.prepareAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );
    }

    function test_prepareAllocation_returnsNonce_and_doesNotIncrementStorage() public {
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), defaultAmount);

        // call from an arbitrary EOA (caller)
        vm.prank(caller);
        uint256 returnedNonce = allocator.prepareAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        assertEq(returnedNonce, _composeNonceUint(address(0), 1));
        // storage nonce is only incremented in executeAllocation (on-chain allocations use address(0))
        assertEq(allocator.nonces(address(0)), 0);
    }

    function test_prepareAllocation_revert_InvalidExpiration() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        vm.expectRevert(
            abi.encodeWithSelector(
                IOnChainAllocator.InvalidExpiration.selector, uint256(type(uint32).max) + 1, type(uint32).max
            )
        );
        allocator.prepareAllocation(
            recipient, idsAndAmounts, arbiter, uint256(type(uint32).max) + 1, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );
    }

    function test_executeAllocation_revert_InvalidExpiration() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        vm.expectRevert(
            abi.encodeWithSelector(
                IOnChainAllocator.InvalidExpiration.selector, uint256(type(uint32).max) + 1, type(uint32).max
            )
        );
        allocator.executeAllocation(
            recipient, idsAndAmounts, arbiter, uint256(type(uint32).max) + 1, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );
    }

    function test_executeAllocation_success_viaCaller_singleERC20() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        // fund and approve from allocationCaller
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // Check nonce previous to the allocation (on-chain allocations use address(0))
        assertEq(allocator.nonces(address(0)), 0);

        // run the whole flow in a single tx through the helper
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
        );
        vm.snapshotGasLastCall('onchain_execute_single');

        // nonce is scoped to address(0) for on-chain allocations
        assertEq(allocator.nonces(address(0)), 1);
        uint256 expectedNonce = _composeNonceUint(address(0), 1);

        // compute claim hash and check authorization
        Lock[] memory commitments = _idsAndAmountsToCommitments(idsAndAmounts);
        bytes32 claimHash =
            _createClaimHash(recipient, arbiter, expectedNonce, defaultExpiration, commitments, bytes32(0));

        assertTrue(
            allocator.isClaimAuthorized(
                claimHash, arbiter, recipient, expectedNonce, defaultExpiration, idsAndAmounts, ''
            )
        );
    }

    /// forge-config: default.isolate = false
    function test_executeAllocation_revert_multiplePreparations() public {
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), defaultAmount);

        uint256[2][] memory idsAndAmountsCrooked = new uint256[2][](2);
        idsAndAmountsCrooked[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0)); // additionally use another ids to receive a unique identifier slot
        idsAndAmountsCrooked[0][1] = defaultAmount;
        idsAndAmountsCrooked[1] = idsAndAmounts[0]; // Crooked idsAndAmounts is also using USDC as the same ID, among others

        usdc.mint(address(this), defaultAmount);
        usdc.approve(address(compact), defaultAmount);

        // prepare for the recipient using caller 1
        vm.prank(recipient);
        uint256 nonce1 = allocator.prepareAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        // prepare for second recipient - DIFFERENT CALLER TO RECEIVE A DIFFERENT NONCE SLOT
        vm.prank(address(this));
        uint256 nonce2 = allocator.prepareAllocation(
            recipient, idsAndAmountsCrooked, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        assertEq(nonce1, _composeNonceUint(address(0), 1));
        assertEq(nonce2, _composeNonceUint(address(0), 1));

        // We do a single deposit of usdc with defaultAmount. This would mean, that we SHOULD only able to allocate defaultAmount of usdc
        ITheCompact(compact).batchDeposit{value: defaultAmount}(idsAndAmountsCrooked, recipient);

        // Crooked registrations: we register two claims that would each use all of the usdc (so defaultAmount * 2 combined)
        Lock[] memory commitments = _idsAndAmountsToCommitments(idsAndAmounts);
        bytes32 claimHash1Crooked =
            _createClaimHash(recipient, arbiter, nonce1, defaultExpiration, commitments, bytes32(0));
        Lock[] memory commitmentsCrooked = _idsAndAmountsToCommitments(idsAndAmountsCrooked);
        bytes32 claimHash2Crooked =
            _createClaimHash(recipient, arbiter, nonce2, defaultExpiration, commitmentsCrooked, bytes32(0));
        vm.prank(recipient);
        ITheCompact(compact).register(claimHash1Crooked, BATCH_COMPACT_TYPEHASH);
        vm.prank(recipient);
        ITheCompact(compact).register(claimHash2Crooked, BATCH_COMPACT_TYPEHASH);

        // execute for first allocation
        vm.prank(recipient);
        allocator.executeAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        // execute for second allocation which must fail
        vm.prank(address(this));
        vm.expectRevert(abi.encodeWithSelector(AllocatorLib.InvalidPreparation.selector));
        allocator.executeAllocation(
            recipient, idsAndAmountsCrooked, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        assertTrue(
            allocator.isClaimAuthorized(
                claimHash1Crooked, arbiter, recipient, nonce1, defaultExpiration, idsAndAmounts, ''
            )
        );
        assertFalse(
            allocator.isClaimAuthorized(
                claimHash2Crooked, arbiter, recipient, nonce2, defaultExpiration, idsAndAmounts, ''
            )
        );
    }

    /// forge-config: default.isolate = false
    function test_executeAllocation_revert_multipleDifferentPreparations(address recipient1, address recipient2)
        public
    {
        vm.assume(recipient1 != address(0));
        vm.assume(recipient2 != address(0));
        vm.assume(recipient1 != recipient2);

        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), defaultAmount);

        uint256 previousBalance = 1_000_000;
        usdc.mint(address(this), previousBalance + 2 * defaultAmount);
        usdc.approve(address(compact), previousBalance + 2 * defaultAmount);

        // deposit funds to recipient1
        compact.depositERC20(
            address(usdc),
            _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes),
            previousBalance,
            recipient1
        );

        // Check nonce previous to the allocation
        assertEq(allocator.nonces(address(0)), 0);

        // prepare for first recipient
        vm.prank(recipient1);
        uint256 nonce1 = allocator.prepareAllocation(
            recipient1, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        // prepare for second recipient
        vm.prank(recipient2);
        uint256 nonce2 = allocator.prepareAllocation(
            recipient2, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        assertEq(nonce1, _composeNonceUint(address(0), 1));
        assertEq(nonce2, _composeNonceUint(address(0), 1));
        // The provided nonces should be the same because they use the same pool of nonces, independent of the recipient or caller
        assertEq(nonce1, nonce2);

        // compute claim hash and check authorization
        Lock[] memory commitments = _idsAndAmountsToCommitments(idsAndAmounts);
        bytes32 claimHash1 = _createClaimHash(recipient1, arbiter, nonce1, defaultExpiration, commitments, bytes32(0));
        bytes32 claimHash2 = _createClaimHash(recipient2, arbiter, nonce2, defaultExpiration, commitments, bytes32(0));

        ITheCompact(compact).batchDepositAndRegisterFor(
            recipient1, idsAndAmounts, arbiter, nonce1, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );

        ITheCompact(compact).batchDepositAndRegisterFor(
            recipient2, idsAndAmounts, arbiter, nonce2, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );

        // execute for first recipient
        vm.prank(recipient1);
        allocator.executeAllocation(
            recipient1, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        // execute for second recipient
        vm.prank(recipient2);
        vm.expectRevert(abi.encodeWithSelector(AllocatorLib.InvalidPreparation.selector));
        allocator.executeAllocation(
            recipient2, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        assertTrue(
            allocator.isClaimAuthorized(claimHash1, arbiter, recipient1, nonce1, defaultExpiration, idsAndAmounts, '')
        );
        assertFalse(
            allocator.isClaimAuthorized(claimHash2, arbiter, recipient2, nonce2, defaultExpiration, idsAndAmounts, '')
        );
    }

    function test_executeAllocation_revert_InvalidPreparation() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        // fund and approve from allocationCaller
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // todo = 2: deposit+register without prepareAllocation -> executeAllocation must revert InvalidPreparation
        vm.prank(user);
        vm.expectRevert(AllocatorLib.InvalidPreparation.selector);
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 2
        );
    }

    function test_executeAllocation_revert_InvalidRegistration() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        // fund and approve from allocationCaller
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // todo = 1: deposit only (no registration) -> executeAllocation must revert InvalidRegistration
        // Expect the precise error and arguments from AllocatorLib
        // Compute the claimHash that AllocatorLib will recompute during execute.
        Lock[] memory commitments = _idsAndAmountsToCommitments(idsAndAmounts);
        bytes32 expectedClaimHash = _createClaimHash(
            recipient,
            arbiter,
            _composeNonceUint(address(0), 1), // On-chain allocations use address(0) in nonce
            defaultExpiration,
            commitments,
            bytes32(0)
        );
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                AllocatorLib.InvalidRegistration.selector, recipient, expectedClaimHash, BATCH_COMPACT_TYPEHASH
            )
        );
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 1
        );
    }

    function test_executeAllocation_revert_InvalidBalanceChange_onZeroAmountSecondId() public {
        uint256 amountA = defaultAmount;
        uint256 amountB = 0; // no deposit for second id -> balance unchanged -> InvalidBalanceChange
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor2(address(usdc), amountA, address(dai), amountB);

        // fund and approve only the first token
        usdc.mint(address(allocationCaller), amountA);
        vm.startPrank(address(allocationCaller));
        usdc.approve(address(compact), amountA);
        // approve DAI even if amount is zero to avoid allowance issues
        dai.approve(address(compact), 0);
        vm.stopPrank();

        // Even though registration will succeed (with 0 for the second id), executeAllocation should revert
        vm.prank(user);
        // Revert happens inside TheCompact deposit logic before executeAllocation runs
        // Use the selector for InvalidDepositBalanceChange()
        vm.expectRevert(bytes4(keccak256('InvalidDepositBalanceChange()')));
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
        );
    }

    function test_executeAllocation_success_twoIds() public {
        uint256 amountA = defaultAmount;
        uint256 amountB = defaultAmount / 2;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor2(address(usdc), amountA, address(dai), amountB);

        // fund & approve caller for both tokens
        usdc.mint(address(allocationCaller), amountA);
        dai.mint(address(allocationCaller), amountB);
        vm.startPrank(address(allocationCaller));
        usdc.approve(address(compact), amountA);
        dai.approve(address(compact), amountB);
        vm.stopPrank();

        vm.prank(user);
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
        );
        vm.snapshotGasLastCall('onchain_execute_double');

        // authorization with the measured amounts
        uint256 expectedNonce = _composeNonceUint(address(0), 1);

        assertTrue(
            allocator.isClaimAuthorized(
                _createClaimHash(
                    recipient,
                    arbiter,
                    expectedNonce,
                    defaultExpiration,
                    _idsAndAmountsToCommitments(idsAndAmounts),
                    bytes32(0)
                ),
                arbiter,
                recipient,
                expectedNonce,
                defaultExpiration,
                idsAndAmounts,
                ''
            )
        );
    }

    function test_executeAllocation_revert_InvalidBalanceChange_noDeposit() public {
        // Prepare only, no deposit → newBalance <= oldBalance → InvalidBalanceChange
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        // Give recipient a prior ERC6909 balance so revert is not (0,0)
        bytes12 lockTag = _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes);
        vm.startPrank(user);
        usdc.mint(user, amount);
        usdc.approve(address(compact), amount);
        compact.depositERC20(address(usdc), lockTag, amount, recipient);
        vm.stopPrank();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature('InvalidBalanceChange(uint256,uint256)', amount, amount));
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 3
        );
    }

    function test_executeAllocation_revert_InvalidPreparation_replaySameTx() public {
        // First execute succeeds; second execute in same tx (without new prepare) must fail with InvalidPreparation
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        // fund and approve caller for deposit
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        vm.prank(user);
        vm.expectRevert(AllocatorLib.InvalidPreparation.selector);
        // todo=4 triggers deposit+register + execute, then a second execute at function end
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 4
        );
    }

    function test_executeAllocation_fullAllocation_preventsFurtherAllocate() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        // fund and approve caller for deposit
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // perform correct prepare + deposit + register + execute
        vm.prank(user);
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
        );

        // Now the whole balance is allocated for recipient; another allocate should fail
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), 1);

        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));

        vm.prank(recipient);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, recipient, id, 0, 1));
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_executeAllocation_revert_InvalidAmount_largeDeposit() public {
        // Deposit an amount > uint224.max so executeAllocation reverts on range check
        uint256 largeAmount = uint256(type(uint224).max) + 1;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), largeAmount);

        // fund and approve caller for large amount
        usdc.mint(address(allocationCaller), largeAmount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), largeAmount);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, largeAmount));
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
        );
    }

    function test_allocateAndRegister_revert_InvalidCommitments() public {
        Lock[] memory commitments = new Lock[](0);

        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidCommitments.selector));
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_InvalidAmount_native() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), 1 ether);

        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, commitments[0].amount));
        allocator.allocateAndRegister{value: commitments[0].amount + 1}(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_InvalidAmount_native_with_zero_deposit() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), 0 ether);

        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, 0));
        allocator.allocateAndRegister{value: 0}(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_InvalidAmount_non_native_with_non_zero_native_call() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), 1);

        uint256 amount = 1;
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, amount));
        allocator.allocateAndRegister{value: amount}(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_invalidExpiration() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        usdc.mint(address(allocator), defaultAmount);

        vm.warp(defaultExpiration);

        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidExpiration.selector, defaultExpiration, block.timestamp)
        );
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_InvalidAmount() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), uint256(type(uint224).max) + 1);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, commitments[0].amount));
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_InvalidAmount_balance() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), 0);
        usdc.mint(address(allocator), uint256(type(uint224).max) + 1);

        vm.prank(caller);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, uint256(type(uint224).max) + 1)
        );
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_InvalidAllocator() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);
        commitments[0].lockTag = bytes12(commitments[0].lockTag & bytes12(0x110000000000000000000000));

        vm.prank(caller);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidAllocator.selector, 0, allocator.ALLOCATOR_ID())
        );
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_success_singleERC20() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        usdc.mint(address(allocator), defaultAmount);

        vm.prank(caller);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(nonce, _composeNonceUint(address(0), 1));
        assertEq(registeredAmounts.length, 1);
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(ERC6909(address(compact)).balanceOf(recipient, idsAndAmounts[0][0]), defaultAmount);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, recipient, nonce, defaultExpiration, idsAndAmounts, '')
        );
        assertTrue(compact.isRegistered(recipient, claimHash, BATCH_COMPACT_TYPEHASH));
        bytes32 claimHashRecreated =
            _createClaimHash(recipient, arbiter, nonce, defaultExpiration, commitments, bytes32(0));
        assertEq(claimHashRecreated, claimHash);
    }

    function test_allocateAndRegister_success_singleERC20_withWitness(bytes32 witness) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        bytes32 typehash = witness == bytes32(0) ? BATCH_COMPACT_TYPEHASH : BATCH_COMPACT_TYPEHASH_WITH_WITNESS;

        usdc.mint(address(allocator), defaultAmount);

        vm.prank(caller);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) =
            allocator.allocateAndRegister(recipient, commitments, arbiter, defaultExpiration, typehash, witness);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(nonce, _composeNonceUint(address(0), 1));
        assertEq(registeredAmounts.length, 1);
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(ERC6909(address(compact)).balanceOf(recipient, idsAndAmounts[0][0]), defaultAmount);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, recipient, nonce, defaultExpiration, idsAndAmounts, '')
        );
        assertTrue(compact.isRegistered(recipient, claimHash, typehash));
        bytes32 claimHashRecreated =
            _createClaimHash(recipient, arbiter, nonce, defaultExpiration, commitments, witness);
        assertEq(claimHashRecreated, claimHash);
    }

    function test_allocateAndRegister_success_amountZeroDepositsFullBalance(bytes32 witness) public {
        uint256 depositAmount = 5 ether;
        usdc.mint(address(allocator), depositAmount);

        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), 0);

        vm.prank(caller);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, witness
        );

        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));

        assertEq(registeredAmounts[0], depositAmount);
        assertEq(usdc.balanceOf(address(allocator)), 0);
        assertEq(ERC6909(address(compact)).balanceOf(recipient, id), depositAmount);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = id;
        idsAndAmounts[0][1] = depositAmount;

        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, recipient, nonce, defaultExpiration, idsAndAmounts, '')
        );
    }

    function test_allocateAndRegister_success_multipleERC20() public {
        uint256 amount1 = 1 ether;
        uint256 amount2 = 2 ether;

        usdc.mint(address(allocator), amount1);
        dai.mint(address(allocator), amount2);

        Lock[] memory commitments = new Lock[](2);
        commitments[0] = _makeLock(address(usdc), amount1);
        commitments[1] = _makeLock(address(dai), amount2);

        vm.prank(caller);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );

        uint256 id1 = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        uint256 id2 = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(dai));

        assertEq(registeredAmounts.length, 2);
        assertEq(registeredAmounts[0], amount1);
        assertEq(registeredAmounts[1], amount2);

        assertEq(ERC6909(address(compact)).balanceOf(recipient, id1), amount1);
        assertEq(ERC6909(address(compact)).balanceOf(recipient, id2), amount2);

        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = id1;
        idsAndAmounts[0][1] = amount1;
        idsAndAmounts[1][0] = id2;
        idsAndAmounts[1][1] = amount2;

        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, recipient, nonce, defaultExpiration, idsAndAmounts, '')
        );
    }

    function test_allocateAndRegister_success_multiple() public {
        uint256 amount1 = 1 ether;
        uint256 amount2 = 2 ether;

        usdc.mint(address(allocator), amount2);

        Lock[] memory commitments = new Lock[](2);
        commitments[0] = _makeLock(address(0), amount1);
        commitments[1] = _makeLock(address(usdc), amount2);

        vm.deal(caller, amount1);
        vm.prank(caller);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: amount1
        }(recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        uint256 id1 = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        uint256 id2 = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));

        assertEq(registeredAmounts.length, 2);
        assertEq(registeredAmounts[0], amount1);
        assertEq(registeredAmounts[1], amount2);

        assertEq(ERC6909(address(compact)).balanceOf(recipient, id1), amount1);
        assertEq(ERC6909(address(compact)).balanceOf(recipient, id2), amount2);

        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = id1;
        idsAndAmounts[0][1] = amount1;
        idsAndAmounts[1][0] = id2;
        idsAndAmounts[1][1] = amount2;

        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, recipient, nonce, defaultExpiration, idsAndAmounts, '')
        );
    }

    function test_constructor_allowsPreRegisteredAllocator_create2() public {
        OnChainAllocatorFactory factory = new OnChainAllocatorFactory();

        bytes32 salt = keccak256('onchain-allocator-pre-registered');
        // OnChainAllocator constructor takes no arguments, so initCode is just creationCode
        bytes memory initCode = type(OnChainAllocator).creationCode;
        bytes32 initCodeHash = keccak256(initCode);

        address expected = vm.computeCreate2Address(salt, initCodeHash, address(factory));

        bytes memory proof = abi.encodePacked(bytes1(0xff), address(factory), salt, initCodeHash);

        uint96 preId = compact.__registerAllocator(expected, proof);
        assertEq(_toAllocatorId(expected), preId);

        address deployed = OnChainAllocatorFactory(address(factory)).deploy(salt);
        assertEq(deployed, expected);

        OnChainAllocator newAllocator = OnChainAllocator(deployed);
        assertEq(newAllocator.ALLOCATOR_ID(), _toAllocatorId(deployed));
    }

    function test_constructor_reverts_with_already_registered_allocator_in_case_of_address_collision() public {
        // Deploy Create2 factory
        OnChainAllocatorFactory factory = new OnChainAllocatorFactory();

        // Precalculate the allocator's address
        bytes32 salt = keccak256('onchain-allocator-pre-registered');
        // OnChainAllocator constructor takes no arguments, so initCode is just creationCode
        bytes memory initCode = type(OnChainAllocator).creationCode;
        bytes32 initCodeHash = keccak256(initCode);

        address expected = vm.computeCreate2Address(salt, initCodeHash, address(factory));

        // Store a different registered allocator address (simulate an address collision)
        address differentRegisteredAllocator = address(1);

        uint96 allocatorId = IdLib.toAllocatorId(expected);
        bytes32 allocatorSlot;
        assembly ("memory-safe") {
            allocatorSlot := or(0x000044036fc77deaed2300000000000000000000000, allocatorId)
        }

        vm.store(address(compact), allocatorSlot, bytes32(uint256(uint160(differentRegisteredAllocator))));

        // Try to deploy the allocator
        // Should revert with the InvalidAllocatorRegistration error, since The Compact has a different address stored in the allocator's slot
        vm.expectRevert(
            abi.encodeWithSelector(
                IOnChainAllocator.InvalidAllocatorRegistration.selector, differentRegisteredAllocator
            )
        );
        OnChainAllocatorFactory(address(factory)).deploy(salt);
    }

    function test_allocateAndRegister_tokensImmediatelyAllocated() public {
        uint256 amount1 = 1 ether;
        uint256 amount2 = 2 ether;

        usdc.mint(address(allocator), amount1);
        dai.mint(address(allocator), amount2);

        Lock[] memory commitments = new Lock[](2);
        commitments[0] = _makeLock(address(usdc), amount1);
        commitments[1] = _makeLock(address(dai), amount2);

        vm.prank(caller);
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );

        uint256 id1 = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        uint256 id2 = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(dai));

        assertEq(ERC6909(address(compact)).balanceOf(recipient, id1), amount1);
        assertEq(ERC6909(address(compact)).balanceOf(recipient, id2), amount2);

        // Try to send a single unit of the tokens

        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, recipient, id1, 0, 1));
        allocator.attest(address(this), recipient, address(this), id1, 1);

        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, recipient, id2, 0, 1));
        allocator.attest(address(this), recipient, address(this), id2, 1);
    }

    function test_allocateAndRegister_emptyRecipientBecomesCaller() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        usdc.mint(address(allocator), defaultAmount);

        vm.prank(caller);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister(
            address(0), /* allocate for an empty recipient */
            commitments,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0)
        );

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(nonce, 1);
        assertEq(registeredAmounts.length, 1);
        assertEq(registeredAmounts[0], defaultAmount);
        // Ensure the allocation happened for the caller, not address(0)
        assertEq(ERC6909(address(compact)).balanceOf(caller, idsAndAmounts[0][0]), defaultAmount);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, caller, nonce, defaultExpiration, idsAndAmounts, ''));
        assertTrue(compact.isRegistered(caller, claimHash, BATCH_COMPACT_TYPEHASH));
        bytes32 claimHashRecreated =
            _createClaimHash(caller, arbiter, nonce, defaultExpiration, commitments, bytes32(0));
        assertEq(claimHashRecreated, claimHash);
    }

    /* --------------------------------------------------------------------- */
    /*                  Reentrancy Protection Tests                         */
    /* --------------------------------------------------------------------- */

    /**
     * @notice Tests that allocate() reverts when called during active reentrancy guard.
     * @dev This simulates an attack where a malicious recipient tries to call allocate()
     *      from within its receive() function when receiving native tokens during a claim.
     *      The settledBalanceOf() check should detect the active reentrancy guard and
     *      revert with BalanceNotSettled().
     */
    function test_allocate_revert_BalanceNotSettled_duringReentrancy() public {
        // Step 1: Setup - maliciousRecipient deposits and allocates native tokens using OnChainAllocator
        (uint256 id, bytes32 claimHash, uint256 nonce) = _setupNativeTokenReentrancyTest();

        // Step 2: Configure maliciousRecipient to attempt reentrant allocate() on the second allocation
        Lock[] memory reentrantCommitments = new Lock[](1);
        reentrantCommitments[0] = Lock({
            lockTag: _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes),
            token: address(0), // native token
            amount: defaultAmount
        });
        maliciousRecipient.setReentrantCommitments(reentrantCommitments);
        maliciousRecipient.setAttemptReentrancy(true);
        maliciousRecipient.setAttackType(MaliciousRecipient.AttackType.ALLOCATE);

        // Step 3: Create withdrawal batch claim for the deposit (using OnChainAllocator)
        BatchClaim memory claim = _createClaimForMaliciousRecipient(id, nonce, defaultAmount);

        assertEq(address(compact).balance, defaultAmount, 'TheCompact should have the deposited balance');
        assertEq(
            compact.balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should have a balance in TheCompact'
        );

        // Step 5: Execute batch claim
        // Flow:
        // 1. MaliciousRecipient calls compact.batchClaim() to withdraw first deposit
        // 2. TheCompact validates via ERC1271 or registration (isValidSignature returns success)
        // 3. TheCompact validates via OnChainAllocator (checks stored claimHash)
        // 4. TheCompact sends native tokens to maliciousRecipient (withdrawal)
        // 5. MaliciousRecipient's receive() is called with reentrancy guard ACTIVE
        // 6. receive() tries to call allocator.allocate() to allocate the deposited tokens again in flight
        // 7. allocate() calls _checkBalance() -> settledBalanceOf()
        // 8. settledBalanceOf() detects active reentrancy guard → reverts with BalanceNotSettled()
        // 9. receive() reverts the ETH transaction, will transfer the ERC6909 as a backup (which remains the same balance)
        // Result: Claim succeeds, withdrawal completes, but reentrancy attack was prevented!
        vm.prank(address(maliciousRecipient));
        vm.expectEmit(true, true, true, true, address(compact));
        emit ITheCompact.Claim(
            address(maliciousRecipient), address(allocator), address(maliciousRecipient), claimHash, nonce
        );
        compact.batchClaim(claim);

        // Verify: The reentrant allocation did NOT happen (balance unchanged in compact)
        // If the attack succeeded, MaliciousRecipient would have allocated half of the second deposit
        assertEq(
            compact.balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should still have his balance in TheCompact'
        );

        // Verify: The withdrawal DID succeed to wrapped format
        // This is because allocate() reverts and blocks the receive() function.
        // The compact will continue to just send the ERC6909 tokens instaed
        assertEq(address(maliciousRecipient).balance, 0, 'Withdrawal should have completed, but in wrapped format');
        assertEq(address(compact).balance, defaultAmount, 'TheCompact should have the deposited balance');
        assertEq(
            ERC6909(address(compact)).balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should still have his balance in TheCompact'
        );
    }

    /**
     * @notice Tests that allocate() succeeds when reentrancy is not attempted.
     * @dev This is the control test showing normal operation works correctly.
     */
    function test_allocate_succeeds_withoutReentrancy() public {
        // Setup - maliciousRecipient deposits and allocates native tokens
        (uint256 id, bytes32 claimHash, uint256 nonce) = _setupNativeTokenReentrancyTest();

        // Do NOT enable reentrancy attempt
        maliciousRecipient.setAttemptReentrancy(false);

        // Create and execute withdrawal batch claim
        BatchClaim memory claim = _createClaimForMaliciousRecipient(id, nonce, defaultAmount);

        assertEq(address(compact).balance, defaultAmount, 'TheCompact should have the deposited balance');
        assertEq(
            compact.balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should have a balance in TheCompact'
        );

        // MaliciousRecipient calls batchClaim() to withdraw its own tokens
        // ERC1271 validation passes, allocator validation passes, withdrawal succeeds
        vm.prank(address(maliciousRecipient));
        vm.expectEmit(true, true, true, true, address(compact));
        emit ITheCompact.Claim(
            address(maliciousRecipient), address(allocator), address(maliciousRecipient), claimHash, nonce
        );
        compact.batchClaim(claim);

        // Verify native tokens were withdrawn to maliciousRecipient (successful withdrawal without reentrancy)
        assertEq(address(maliciousRecipient).balance, defaultAmount, 'Should have withdrawn to native ETH');
        assertEq(address(compact).balance, 0, 'TheCompact should have sent the balance');
        assertEq(
            compact.balanceOf(address(maliciousRecipient), id), 0, 'Balance should have been withdrawn from TheCompact'
        );
    }

    /**
     * @notice Tests that attest() succeeds during ERC6909 token transfer when no allocation exists.
     * @dev When a user performs a direct ERC6909 transfer(), the _beforeTokenTransfer hook is called
     *      which sets the reentrancy guard and calls _ensureAttested(), which in turn calls
     *      allocator.attest(). The attest() function uses raw balanceOf() (not settledBalanceOf()),
     *      so it should succeed even with the reentrancy guard active.
     *
     *      Test flow:
     *      1. User deposits tokens via TheCompact (no allocation)
     *      2. User performs direct ERC6909 transfer to recipient
     *      3. _beforeTokenTransfer() sets reentrancy guard and calls _ensureAttested()
     *      4. _ensureAttested() calls allocator.attest()
     *      5. Expected: attest() succeeds because tokens are not allocated
     */
    function test_attest_succeeds_duringTokenTransfer() public {
        // Setup: User deposits tokens WITHOUT allocating
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        bytes12 lockTag = commitments[0].lockTag;
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);
        vm.prank(user);
        uint256 id = compact.depositERC20(address(usdc), lockTag, defaultAmount, user);

        // Verify initial balances
        assertEq(compact.balanceOf(user, id), defaultAmount, 'User should have deposited tokens');
        assertEq(compact.balanceOf(recipient, id), 0, 'Recipient should have no tokens');

        // User performs a direct ERC6909 transfer (not a claim, just a transfer)
        // This triggers _beforeTokenTransfer → _setReentrancyGuard() → _ensureAttested() → allocator.attest()
        vm.prank(user);
        compact.transfer(recipient, id, defaultAmount);

        // Verify transfer succeeded
        assertEq(compact.balanceOf(user, id), 0, 'User should have transferred all tokens');
        assertEq(compact.balanceOf(recipient, id), defaultAmount, 'Recipient should have received tokens');
    }

    /**
     * @notice Tests that ERC6909 token transfer fails when tokens are allocated.
     * @dev After allocation, tokens cannot be transferred directly via ERC6909 transfer()
     *      because attest() will detect the allocation and revert.
     *
     *      Test flow:
     *      1. User deposits tokens and allocates them
     *      2. User attempts direct ERC6909 transfer to recipient
     *      3. _beforeTokenTransfer() calls _ensureAttested() → allocator.attest()
     *      4. Expected: attest() reverts because tokens are allocated
     */
    function test_attest_revert_duringTokenTransfer_afterAllocation() public {
        // Setup: User deposits and allocates tokens
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        bytes12 lockTag = commitments[0].lockTag;
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);
        vm.prank(user);
        uint256 id = compact.depositERC20(address(usdc), lockTag, defaultAmount, user);

        // User allocates the tokens
        vm.prank(user);
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        // Verify initial balances
        assertEq(compact.balanceOf(user, id), defaultAmount, 'User should have deposited tokens');
        assertEq(compact.balanceOf(recipient, id), 0, 'Recipient should have no tokens');

        // User attempts to perform a direct ERC6909 transfer of allocated tokens
        // This should fail because attest() will detect insufficient unlocked balance
        // Available balance = total balance - allocated balance = defaultAmount - defaultAmount = 0
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, user, id, 0, defaultAmount)
        );
        compact.transfer(recipient, id, defaultAmount);

        // Verify transfer failed - balances unchanged
        assertEq(compact.balanceOf(user, id), defaultAmount, 'User should still have all tokens');
        assertEq(compact.balanceOf(recipient, id), 0, 'Recipient should still have no tokens');
    }

    /**
     * @notice Tests that prepareAllocation() reverts when called during active reentrancy guard.
     * @dev This tests the checkCompactReentrancyGuardAndRevert() protection in AllocatorLib.
     *      prepareAllocation() explicitly checks the compact's reentrancy guard and reverts
     *      with CompactReentrancyGuardActive() error (selector 0x87621186).
     *
     *      Test flow:
     *      1. User deposits native tokens and allocates to maliciousRecipient
     *      2. Configure maliciousRecipient to attempt reentrant prepareAllocation()
     *      3. Arbiter claims → TheCompact sends native to maliciousRecipient
     *      4. MaliciousRecipient's receive() triggered (guard ACTIVE)
     *      5. Inside receive(), attempts prepareAllocation()
     *      6. Expected: checkCompactReentrancyGuardAndRevert() reverts with CompactReentrancyGuardActive()
     */
    function test_prepareAllocation_revert_CompactReentrancyGuardActive() public {
        // Setup - maliciousRecipient deposits and allocates native tokens
        (uint256 id, bytes32 claimHash, uint256 nonce) = _setupNativeTokenReentrancyTest();

        // Configure maliciousRecipient to attempt reentrant prepareAllocation()
        uint256[2][] memory reentrantIdsAndAmounts = new uint256[2][](1);
        reentrantIdsAndAmounts[0][0] = id;
        reentrantIdsAndAmounts[0][1] = defaultAmount;
        maliciousRecipient.setReentrantPrepareData(
            reentrantIdsAndAmounts,
            address(maliciousRecipient),
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0)
        );
        maliciousRecipient.setAttemptReentrancy(true);
        maliciousRecipient.setAttackType(MaliciousRecipient.AttackType.PREPARE);

        // Create withdrawal claim
        BatchClaim memory claim = _createClaimForMaliciousRecipient(id, nonce, defaultAmount);
        assertEq(address(maliciousRecipient).balance, 0, 'Malicious recipient should not have a balance');
        assertEq(
            ERC6909(address(compact)).balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should have a balance in TheCompact'
        );

        // Execute batch claim
        // prepareAllocation() calls checkCompactReentrancyGuardAndRevert() in AllocatorLib
        // which detects the active guard and reverts with CompactReentrancyGuardActive()
        // But TheCompact catches the revert and continues (withdrawal still completes)
        vm.prank(address(maliciousRecipient));
        vm.expectEmit(true, true, true, true, address(compact));
        emit ITheCompact.Claim(
            address(maliciousRecipient), address(allocator), address(maliciousRecipient), claimHash, nonce
        );
        compact.batchClaim(claim);

        // Verify: The withdrawal did succeed, but only in 6909 wrapped form (which means no change in balance)
        assertEq(address(maliciousRecipient).balance, 0, 'Malicious recipient should still not have a balance');
        assertEq(
            ERC6909(address(compact)).balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should still have his balance in TheCompact'
        );
    }

    /**
     * @notice Tests that executeAllocation() reverts when called during active reentrancy guard.
     * @dev This tests the checkCompactReentrancyGuardAndRevert() protection in AllocatorLib.
     *      executeAllocation() explicitly checks the compact's reentrancy guard and reverts
     *      with CompactReentrancyGuardActive() error (selector 0x87621186).
     *
     *      Test flow:
     *      1. User deposits native tokens and allocates to maliciousRecipient
     *      2. Configure maliciousRecipient to attempt reentrant executeAllocation()
     *      3. Arbiter claims → TheCompact sends native to maliciousRecipient
     *      4. MaliciousRecipient's receive() triggered (guard ACTIVE)
     *      5. Inside receive(), attempts executeAllocation()
     *      6. Expected: checkCompactReentrancyGuardAndRevert() reverts with CompactReentrancyGuardActive()
     */
    function test_executeAllocation_revert_CompactReentrancyGuardActive() public {
        // Setup - maliciousRecipient deposits and allocates native tokens
        (uint256 id, bytes32 claimHash, uint256 nonce) = _setupNativeTokenReentrancyTest();

        // Configure maliciousRecipient to attempt reentrant executeAllocation()
        uint256[2][] memory reentrantIdsAndAmounts = new uint256[2][](1);
        reentrantIdsAndAmounts[0][0] = id;
        reentrantIdsAndAmounts[0][1] = defaultAmount;
        maliciousRecipient.setReentrantPrepareData(
            reentrantIdsAndAmounts,
            address(maliciousRecipient),
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0)
        );
        maliciousRecipient.setAttemptReentrancy(true);
        maliciousRecipient.setAttackType(MaliciousRecipient.AttackType.EXECUTE);

        // Create withdrawal claim
        BatchClaim memory claim = _createClaimForMaliciousRecipient(id, nonce, defaultAmount);
        assertEq(address(maliciousRecipient).balance, 0, 'Malicious recipient should not have a balance');
        assertEq(
            ERC6909(address(compact)).balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should have a balance in TheCompact'
        );

        // Execute batch claim
        // executeAllocation() calls checkCompactReentrancyGuardAndRevert() in AllocatorLib
        // which detects the active guard and reverts with CompactReentrancyGuardActive()
        // But TheCompact catches the revert and continues (withdrawal still completes)
        vm.prank(address(maliciousRecipient));
        vm.expectEmit(true, true, true, true, address(compact));
        emit ITheCompact.Claim(
            address(maliciousRecipient), address(allocator), address(maliciousRecipient), claimHash, nonce
        );
        compact.batchClaim(claim);

        // Verify: The withdrawal did succeed, but only in 6909 wrapped form (which means no change in balance)
        assertEq(address(maliciousRecipient).balance, 0, 'Malicious recipient should still not have a balance');
        assertEq(
            ERC6909(address(compact)).balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should still have his balance in TheCompact'
        );
    }

    /* --------------------------------------------------------------------- */
    /*                   Tests for permit2Allocation                          */
    /* --------------------------------------------------------------------- */

    function test_permit2Allocation_singleERC20() public {
        bytes12 lockTag = _getLockTag();
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);

        // Prepare token permissions
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), defaultAmount);

        // Prepare deposit details
        DepositDetails memory details = _createDepositDetails(nonce, defaultExpiration, lockTag);

        // Compute ids
        uint256[] memory ids = new uint256[](1);
        ids[0] = AllocatorLib.toId(lockTag, address(usdc));

        // Compute commitment hashes
        bytes32[] memory commitmentHashes = new bytes32[](1);
        commitmentHashes[0] = _computeCommitmentHash(ids[0], defaultAmount);

        // Compute claimHash (no witness)
        bytes32 claimHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH,
                arbiter,
                user,
                nonce,
                defaultExpiration,
                keccak256(abi.encodePacked(commitmentHashes))
            )
        );

        // Create Permit2 signature
        bytes memory signature = _createPermit2Signature(permitted, details, claimHash, userPK);

        // Execute
        Lock[] memory commitments = allocator.permit2Allocation(user, permitted, details, claimHash, '', signature);
        vm.snapshotGasLastCall('onchain_permit2Allocation_singleERC20');

        // Verify commitments
        assertEq(commitments.length, 1);
        assertEq(commitments[0].lockTag, lockTag);
        assertEq(commitments[0].token, address(usdc));
        assertEq(commitments[0].amount, defaultAmount);

        // Verify claim is authorized
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = ids[0];
        idsAndAmounts[0][1] = defaultAmount;
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        // Verify tokens are in compact
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(compact.balanceOf(user, ids[0]), defaultAmount);
    }

    function test_permit2Allocation_multipleERC20() public {
        bytes12 lockTag = _getLockTag();
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);
        uint256 amount1 = defaultAmount;
        uint256 amount2 = defaultAmount / 2;

        // Prepare token permissions (sorted by address for Permit2)
        ISignatureTransfer.TokenPermissions[] memory permitted;
        uint256[] memory ids = new uint256[](2);
        bytes32[] memory commitmentHashes = new bytes32[](2);

        if (uint160(address(usdc)) < uint160(address(dai))) {
            permitted = _createTokenPermissions2(address(usdc), amount1, address(dai), amount2);
            ids[0] = AllocatorLib.toId(lockTag, address(usdc));
            ids[1] = AllocatorLib.toId(lockTag, address(dai));
            commitmentHashes[0] = _computeCommitmentHash(ids[0], amount1);
            commitmentHashes[1] = _computeCommitmentHash(ids[1], amount2);
        } else {
            permitted = _createTokenPermissions2(address(dai), amount2, address(usdc), amount1);
            ids[0] = AllocatorLib.toId(lockTag, address(dai));
            ids[1] = AllocatorLib.toId(lockTag, address(usdc));
            commitmentHashes[0] = _computeCommitmentHash(ids[0], amount2);
            commitmentHashes[1] = _computeCommitmentHash(ids[1], amount1);
        }

        // Prepare deposit details
        DepositDetails memory details = _createDepositDetails(nonce, defaultExpiration, lockTag);

        // Compute claimHash (no witness)
        bytes32 claimHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH,
                arbiter,
                user,
                nonce,
                defaultExpiration,
                keccak256(abi.encodePacked(commitmentHashes))
            )
        );

        // Create Permit2 signature
        bytes memory signature = _createPermit2Signature(permitted, details, claimHash, userPK);

        // Execute
        Lock[] memory commitments = allocator.permit2Allocation(user, permitted, details, claimHash, '', signature);
        vm.snapshotGasLastCall('onchain_permit2Allocation_multipleERC20');

        // Verify commitments
        assertEq(commitments.length, 2);

        // Verify claim is authorized
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = ids[0];
        idsAndAmounts[0][1] = permitted[0].amount;
        idsAndAmounts[1][0] = ids[1];
        idsAndAmounts[1][1] = permitted[1].amount;
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        // Verify tokens are in compact
        assertEq(usdc.balanceOf(address(compact)), amount1);
        assertEq(dai.balanceOf(address(compact)), amount2);
    }

    function test_permit2Allocation_revert_invalidNonceCommand() public {
        bytes12 lockTag = _getLockTag();
        // Use ON_CHAIN_NONCE command (0x01) instead of PERMIT2_NONCE (0x03)
        uint256 invalidNonce = uint256(0x01) << 248 | uint256(uint160(user)) << 88 | uint256(1);

        // Prepare token permissions
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), defaultAmount);

        // Prepare deposit details with invalid nonce
        DepositDetails memory details = _createDepositDetails(invalidNonce, defaultExpiration, lockTag);

        // Compute ids and commitment hashes (these are just for signature computation)
        uint256[] memory ids = new uint256[](1);
        ids[0] = AllocatorLib.toId(lockTag, address(usdc));
        bytes32[] memory commitmentHashes = new bytes32[](1);
        commitmentHashes[0] = _computeCommitmentHash(ids[0], defaultAmount);

        bytes32 claimHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH,
                arbiter,
                user,
                invalidNonce,
                defaultExpiration,
                keccak256(abi.encodePacked(commitmentHashes))
            )
        );

        bytes memory signature = _createPermit2Signature(permitted, details, claimHash, userPK);

        // Should revert with UnauthorizedNonce because command is not PERMIT2_NONCE
        vm.expectRevert(abi.encodeWithSelector(AllocatorLib.UnauthorizedNonce.selector, bytes1(0x01), user));
        allocator.permit2Allocation(user, permitted, details, claimHash, '', signature);
    }

    function test_permit2Allocation_revert_invalidExpiration() public {
        bytes12 lockTag = _getLockTag();
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);
        uint256 invalidDeadline = uint256(type(uint32).max) + 1;

        // Prepare token permissions
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), defaultAmount);

        // Prepare deposit details with invalid expiration
        DepositDetails memory details = _createDepositDetails(nonce, invalidDeadline, lockTag);

        bytes32 claimHash = bytes32(uint256(1)); // dummy claim hash
        bytes memory signature = new bytes(64); // dummy signature

        // Should revert because deadline exceeds uint32 max
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidExpiration.selector, invalidDeadline, type(uint32).max)
        );
        allocator.permit2Allocation(user, permitted, details, claimHash, '', signature);
    }

    function test_permit2Allocation_revert_invalidAmount() public {
        bytes12 lockTag = _getLockTag();
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);
        uint256 largeAmount = uint256(type(uint224).max) + 1;

        // Fund user with enough tokens
        usdc.mint(user, largeAmount);
        vm.prank(user);
        usdc.approve(PERMIT2, largeAmount);

        // Prepare token permissions with amount > uint224 max
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), largeAmount);

        // Prepare deposit details
        DepositDetails memory details = _createDepositDetails(nonce, defaultExpiration, lockTag);

        uint256[] memory ids = new uint256[](1);
        ids[0] = AllocatorLib.toId(lockTag, address(usdc));
        bytes32[] memory commitmentHashes = new bytes32[](1);
        commitmentHashes[0] = _computeCommitmentHash(ids[0], largeAmount);

        bytes32 claimHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH,
                arbiter,
                user,
                nonce,
                defaultExpiration,
                keccak256(abi.encodePacked(commitmentHashes))
            )
        );

        bytes memory signature = _createPermit2Signature(permitted, details, claimHash, userPK);

        // Should revert because amount exceeds uint224 max
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, largeAmount));
        allocator.permit2Allocation(user, permitted, details, claimHash, '', signature);
    }

    function test_permit2Allocation_fullClaimFlow() public {
        bytes12 lockTag = _getLockTag();
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);

        // Prepare token permissions
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), defaultAmount);

        // Prepare deposit details
        DepositDetails memory details = _createDepositDetails(nonce, defaultExpiration, lockTag);

        // Compute ids
        uint256 id = AllocatorLib.toId(lockTag, address(usdc));
        bytes32[] memory commitmentHashes = new bytes32[](1);
        commitmentHashes[0] = _computeCommitmentHash(id, defaultAmount);

        // Compute claimHash (no witness)
        bytes32 claimHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH,
                arbiter,
                user,
                nonce,
                defaultExpiration,
                keccak256(abi.encodePacked(commitmentHashes))
            )
        );

        // Create Permit2 signature
        bytes memory signature = _createPermit2Signature(permitted, details, claimHash, userPK);

        // Execute permit2Allocation
        allocator.permit2Allocation(user, permitted, details, claimHash, '', signature);

        // Verify claim is authorized
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = id;
        idsAndAmounts[0][1] = defaultAmount;
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        // Now execute the claim
        address claimRecipient = makeAddr('claimRecipient');
        Component[] memory portions = new Component[](1);
        portions[0] =
            Component({claimant: uint256(bytes32(abi.encodePacked(bytes12(0), claimRecipient))), amount: defaultAmount});

        BatchClaimComponent[] memory claimComponents = new BatchClaimComponent[](1);
        claimComponents[0] = BatchClaimComponent({id: id, allocatedAmount: defaultAmount, portions: portions});

        BatchClaim memory claim = BatchClaim({
            allocatorData: '',
            sponsorSignature: '',
            sponsor: user,
            nonce: nonce,
            expires: details.deadline,
            witness: bytes32(0),
            witnessTypestring: '',
            claims: claimComponents
        });

        // Execute claim
        vm.prank(arbiter);
        bytes32 returnedClaimHash = compact.batchClaim(claim);
        assertEq(returnedClaimHash, claimHash);

        // Verify tokens transferred
        assertEq(usdc.balanceOf(claimRecipient), defaultAmount);
        assertEq(usdc.balanceOf(address(compact)), 0);

        // Verify claim is no longer authorized (deleted after execution)
        assertFalse(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_permit2Allocation_storesAllocationWithExpiration() public {
        bytes12 lockTag = _getLockTag();
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);

        // Prepare token permissions
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), defaultAmount);

        // Prepare deposit details
        DepositDetails memory details = _createDepositDetails(nonce, defaultExpiration, lockTag);

        // Compute ids
        uint256 id = AllocatorLib.toId(lockTag, address(usdc));
        bytes32[] memory commitmentHashes = new bytes32[](1);
        commitmentHashes[0] = _computeCommitmentHash(id, defaultAmount);

        bytes32 claimHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH,
                arbiter,
                user,
                nonce,
                defaultExpiration,
                keccak256(abi.encodePacked(commitmentHashes))
            )
        );

        bytes memory signature = _createPermit2Signature(permitted, details, claimHash, userPK);

        // Execute permit2Allocation
        allocator.permit2Allocation(user, permitted, details, claimHash, '', signature);

        // Verify claim is authorized before expiration
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = id;
        idsAndAmounts[0][1] = defaultAmount;
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        // Warp time past expiration
        vm.warp(defaultExpiration + 1);

        // Verify claim is no longer authorized after expiration
        assertFalse(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_permit2Allocation_blocksTransfersUntilExpiration() public {
        bytes12 lockTag = _getLockTag();
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);

        // Prepare token permissions
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), defaultAmount);

        // Prepare deposit details
        DepositDetails memory details = _createDepositDetails(nonce, defaultExpiration, lockTag);

        // Compute ids and claimHash
        uint256 id = AllocatorLib.toId(lockTag, address(usdc));
        bytes32[] memory commitmentHashes = new bytes32[](1);
        commitmentHashes[0] = _computeCommitmentHash(id, defaultAmount);

        bytes32 claimHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH,
                arbiter,
                user,
                nonce,
                defaultExpiration,
                keccak256(abi.encodePacked(commitmentHashes))
            )
        );

        bytes memory signature = _createPermit2Signature(permitted, details, claimHash, userPK);

        // Execute permit2Allocation
        allocator.permit2Allocation(user, permitted, details, claimHash, '', signature);

        // Try to transfer - should fail because tokens are allocated
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, user, id, 0, defaultAmount)
        );
        compact.transfer(recipient, id, defaultAmount);

        // Warp past expiration
        vm.warp(defaultExpiration + 1);

        // Now transfer should succeed since allocation expired
        vm.prank(user);
        compact.transfer(recipient, id, defaultAmount);

        // Verify transfer succeeded
        assertEq(compact.balanceOf(user, id), 0);
        assertEq(compact.balanceOf(recipient, id), defaultAmount);
    }
}

/* ============================================================================
   Malicious Contract for Reentrancy Testing
   ============================================================================ */

/**
 * @notice Malicious recipient that attempts reentrant allocations during claim/withdrawal.
 * @dev This contract simulates an attacker trying to exploit reentrancy vulnerabilities
 *      by calling allocate(), prepareAllocation(), or executeAllocation() from within
 *      the receive() function which is triggered when TheCompact sends native tokens
 *      during a claim (before the balance is reduced in TheCompact's ERC6909 accounting).
 *
 *      Also implements ERC1271 to allow signature-less claims (always returns valid signature).
 *
 *      Attack flow:
 *      1. MaliciousRecipient deposits native tokens to TheCompact
 *      2. MaliciousRecipient calls allocate() to register allocation with OnChainAllocator
 *      3. MaliciousRecipient creates claim and calls compact.claim()
 *      4. TheCompact validates via ERC1271 (always returns success)
 *      5. TheCompact sends native tokens → receive() triggered (reentrancy guard ACTIVE)
 *      6. MaliciousRecipient attempts reentrant allocation
 *      7. Should revert with appropriate error (BalanceNotSettled or CompactReentrancyGuardActive)
 *
 *      Pattern inspired by CheckBalanceDuringTransfer in the-compact/test/utility/Utility.t.sol
 */
contract MaliciousRecipient is IERC1271 {
    IOnChainAllocation public immutable ALLOCATOR;
    TheCompact public immutable COMPACT;

    bool public attemptReentrancy;

    // Configuration for different attack types
    enum AttackType {
        ALLOCATE,
        PREPARE,
        EXECUTE
    }

    AttackType public attackType;

    // Data for reentrant calls
    Lock[] public reentrantCommitments;
    uint256[2][] public reentrantIdsAndAmounts;
    address public reentrantRecipient;
    address public reentrantArbiter;
    uint256 public reentrantExpires;
    bytes32 public reentrantTypehash;
    bytes32 public reentrantWitness;

    constructor(address allocator, address compact, address /* allocationCaller */ ) {
        ALLOCATOR = IOnChainAllocation(allocator);
        COMPACT = TheCompact(compact);
        attackType = AttackType.ALLOCATE;
    }

    /**
     * @notice Triggered when receiving native tokens during claim.
     * @dev This is where we attempt the reentrant call to test reentrancy protection.
     *      TheCompact's reentrancy guard is ACTIVE at this point (value > 1).
     */
    receive() external payable {
        if (attemptReentrancy) {
            if (attackType == AttackType.ALLOCATE && reentrantCommitments.length > 0) {
                // Attempt reentrant allocation - should fail with BalanceNotSettled()
                // This calls _checkBalance() which uses settledBalanceOf()
                OnChainAllocator(address(ALLOCATOR)).allocate(
                    reentrantCommitments, address(0), uint32(block.timestamp + 100), bytes32(0), bytes32(0)
                );
            } else if (attackType == AttackType.PREPARE && reentrantIdsAndAmounts.length > 0) {
                // Attempt reentrant prepareAllocation - should fail with CompactReentrancyGuardActive()
                // This calls checkCompactReentrancyGuardAndRevert() in AllocatorLib
                ALLOCATOR.prepareAllocation(
                    reentrantRecipient,
                    reentrantIdsAndAmounts,
                    reentrantArbiter,
                    reentrantExpires,
                    reentrantTypehash,
                    reentrantWitness,
                    bytes('')
                );
            } else if (attackType == AttackType.EXECUTE && reentrantIdsAndAmounts.length > 0) {
                // Attempt reentrant executeAllocation - should fail with CompactReentrancyGuardActive()
                // This calls checkCompactReentrancyGuardAndRevert() in AllocatorLib
                ALLOCATOR.executeAllocation(
                    reentrantRecipient,
                    reentrantIdsAndAmounts,
                    reentrantArbiter,
                    reentrantExpires,
                    reentrantTypehash,
                    reentrantWitness,
                    bytes('')
                );
            }
        }
    }

    /**
     * @notice ERC1271 signature validation - always returns valid.
     * @dev This allows TheCompact to validate claims without requiring actual signatures.
     *      TheCompact will call this when sponsorSignature is empty and no pre-registration exists.
     *      Returns the ERC1271 magic value 0x1626ba7e to indicate signature is valid.
     */
    function isValidSignature(bytes32, /* hash */ bytes memory /* signature */ )
        external
        pure
        override
        returns (bytes4)
    {
        return 0x1626ba7e; // ERC1271 magic value
    }

    // Control functions for testing
    function setAttemptReentrancy(bool attempt) external {
        attemptReentrancy = attempt;
    }

    function setAttackType(AttackType _attackType) external {
        attackType = _attackType;
    }

    function setReentrantCommitments(Lock[] calldata commitments) external {
        delete reentrantCommitments;
        for (uint256 i = 0; i < commitments.length; i++) {
            reentrantCommitments.push(commitments[i]);
        }
    }

    function setReentrantPrepareData(
        uint256[2][] calldata idsAndAmounts,
        address recipient,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) external {
        delete reentrantIdsAndAmounts;
        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            reentrantIdsAndAmounts.push(idsAndAmounts[i]);
        }
        reentrantRecipient = recipient;
        reentrantArbiter = arbiter;
        reentrantExpires = expires;
        reentrantTypehash = typehash;
        reentrantWitness = witness;
    }
}
