// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {TestHelper} from './util/TestHelper.sol';
import {ERC20} from '@solady/tokens/ERC20.sol';
import {TheCompact} from '@uniswap/the-compact/TheCompact.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {ISignatureTransfer} from 'permit2/src/interfaces/ISignatureTransfer.sol';

import {BatchClaim} from '@uniswap/the-compact/types/BatchClaims.sol';
import {BatchClaimComponent, Component} from '@uniswap/the-compact/types/Components.sol';

import {DepositDetails} from '@uniswap/the-compact/types/DepositDetails.sol';
import {
    BATCH_COMPACT_TYPEHASH,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FIVE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_SIX,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO,
    BatchCompact,
    LOCK_TYPEHASH,
    Lock
} from '@uniswap/the-compact/types/EIP712Types.sol';
import {ResetPeriod} from '@uniswap/the-compact/types/ResetPeriod.sol';
import {Scope} from '@uniswap/the-compact/types/Scope.sol';

import {Test} from 'forge-std/Test.sol';
import {HybridAllocator} from 'src/allocators/HybridAllocator.sol';

import {IOnChainAllocation} from '@uniswap/the-compact/interfaces/IOnChainAllocation.sol';
import {AllocatorLib} from 'src/allocators/lib/AllocatorLib.sol';
import {BATCH_COMPACT_WITNESS_TYPEHASH} from 'src/allocators/lib/TypeHashes.sol';
import {IHybridAllocator} from 'src/interfaces/IHybridAllocator.sol';
import {ERC20Mock} from 'src/test/ERC20Mock.sol';
import {OnChainAllocationCaller} from 'src/test/OnChainAllocationCaller.sol';
import {DeployTheCompact} from 'test/util/DeployTheCompact.sol';

contract HybridAllocatorFactory {
    function deploy(bytes32 salt, address owner, address signer) external returns (address) {
        return address(new HybridAllocator{salt: salt}(owner, signer));
    }
}

contract HybridAllocatorTest is Test, TestHelper {
    TheCompact compact;
    address arbiter;
    HybridAllocator allocator;
    address owner;
    address signer;
    uint256 signerPrivateKey;
    ERC20Mock usdc;
    ERC20Mock dai;
    address user;
    uint256 userPrivateKey;
    uint256 defaultAmount;
    uint256 defaultExpiration;

    OnChainAllocationCaller allocationCaller;

    BatchCompact batchCompact;

    // Nonce command constants
    bytes1 constant ON_CHAIN_NONCE = 0x01;
    bytes1 constant OFF_CHAIN_NONCE = 0x02;

    // Helper to compose nonces with the command byte
    // For on-chain allocations: address is address(0)
    // For off-chain allocations: address is the sponsor
    function _composeNonceUint(bytes1 command, address a, uint256 nonce) internal pure returns (uint256) {
        return (uint256(uint8(command)) << 248) | (uint256(uint160(a)) << 88) | nonce;
    }

    // Permit2 constants
    address constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    bytes32 constant PERMIT2_DOMAIN_SEPARATOR_TYPEHASH =
        keccak256('EIP712Domain(string name,uint256 chainId,address verifyingContract)');
    bytes32 constant TOKEN_PERMISSIONS_TYPEHASH = keccak256('TokenPermissions(address token,uint256 amount)');

    // BatchActivation typehash for NO witness (from the-compact/src/types/EIP712Types.sol)
    // keccak256(bytes("BatchActivation(address activator,uint256[] ids,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments)Lock(bytes12 lockTag,address token,uint256 amount)"))
    bytes32 constant BATCH_COMPACT_BATCH_ACTIVATION_TYPEHASH =
        0xa794ed1a28cdf297ac45a3eee4643e35d29b295a389368da5f6baa420872c9b7;

    // BatchActivation typehash WITH witness "Mandate(uint256 witness)"
    // The full typestring includes the Mandate struct definition
    string constant BATCH_COMPACT_BATCH_ACTIVATION_WITH_WITNESS_TYPESTRING =
        'BatchActivation(address activator,uint256[] ids,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint256 witness)';
    bytes32 constant BATCH_COMPACT_BATCH_ACTIVATION_WITH_WITNESS_TYPEHASH =
        keccak256(bytes(BATCH_COMPACT_BATCH_ACTIVATION_WITH_WITNESS_TYPESTRING));

    // PermitBatchWitnessTransferFrom typehash (no mandate/witness)
    string constant PERMIT_BATCH_WITNESS_TYPESTRING =
        'PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,BatchActivation witness)BatchActivation(address activator,uint256[] ids,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments)Lock(bytes12 lockTag,address token,uint256 amount)TokenPermissions(address token,uint256 amount)';
    bytes32 constant PERMIT_BATCH_WITNESS_TYPEHASH = keccak256(bytes(PERMIT_BATCH_WITNESS_TYPESTRING));

    // PermitBatchWitnessTransferFrom typehash WITH mandate/witness
    // Used when the permit2Allocation is called with a non-empty witness typestring
    string constant PERMIT_BATCH_WITNESS_WITH_MANDATE_TYPESTRING =
        'PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,BatchActivation witness)BatchActivation(address activator,uint256[] ids,BatchCompact compact)BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint256 witness)TokenPermissions(address token,uint256 amount)';
    bytes32 constant PERMIT_BATCH_WITNESS_WITH_MANDATE_TYPEHASH =
        keccak256(bytes(PERMIT_BATCH_WITNESS_WITH_MANDATE_TYPESTRING));

    function setUp() public {
        compact = DeployTheCompact(new DeployTheCompact()).deployTheCompact();
        assertEq(address(compact), address(0x00000000000000171ede64904551eeDF3C6C9788));

        // Deploy Permit2 at the expected address
        _deployPermit2();

        arbiter = makeAddr('arbiter');
        owner = makeAddr('owner');
        (signer, signerPrivateKey) = makeAddrAndKey('signer');
        allocator = new HybridAllocator(owner, signer);
        usdc = new ERC20Mock('USDC', 'USDC');
        dai = new ERC20Mock('DAI', 'DAI');
        (user, userPrivateKey) = makeAddrAndKey('user');
        deal(user, 10 ether);
        usdc.mint(user, 10 ether);
        dai.mint(user, 10 ether);
        defaultAmount = 1 ether;
        defaultExpiration = vm.getBlockTimestamp() + 1 days;

        // Approve Permit2 for tokens
        vm.startPrank(user);
        usdc.approve(PERMIT2, type(uint256).max);
        dai.approve(PERMIT2, type(uint256).max);
        vm.stopPrank();

        allocationCaller = new OnChainAllocationCaller(address(allocator), address(compact));

        batchCompact.arbiter = arbiter;
        batchCompact.sponsor = user;
        batchCompact.nonce = 1;
        batchCompact.expires = defaultExpiration;
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

    function _idsAndAmounts(address token, uint256 amount) internal view returns (uint256[2][] memory arr) {
        arr = new uint256[2][](1);
        arr[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), token);
        arr[0][1] = amount;
    }

    function _idsAndAmounts2(address tokenA, uint256 amountA, address tokenB, uint256 amountB)
        internal
        view
        returns (uint256[2][] memory arr)
    {
        arr = new uint256[2][](2);
        arr[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), tokenA);
        arr[0][1] = amountA;
        arr[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), tokenB);
        arr[1][1] = amountB;
    }

    /* ====================================================================== */
    /*                     Permit2 Helper Functions                           */
    /* ====================================================================== */

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

    function _createIds(bytes12 lockTag, address[] memory tokens) internal pure returns (uint256[] memory) {
        uint256[] memory ids = new uint256[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            ids[i] = AllocatorLib.toId(lockTag, tokens[i]);
        }
        return ids;
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

    /// @dev Creates an empty additionalCommitmentAmounts array of the specified length
    function _emptyAmounts(uint256 length) internal pure returns (uint256[] memory) {
        return new uint256[](length);
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

    /// @dev Creates a Permit2 signature for allocations WITH a witness/mandate
    function _createPermit2SignatureWithWitness(
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

        // Create activation hash using the WITH_WITNESS typehash since we have a witness
        // The activator is the allocator (msg.sender to TheCompact)
        bytes32 activationHash = keccak256(
            abi.encode(BATCH_COMPACT_BATCH_ACTIVATION_WITH_WITNESS_TYPEHASH, address(allocator), idsHash, claimHash)
        );

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

        // Use the WITH MANDATE typehash since we have a witness
        bytes32 permitBatchHash = keccak256(
            abi.encode(
                PERMIT_BATCH_WITNESS_WITH_MANDATE_TYPEHASH,
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

    function test_constructor_revert_ownerIsAddressZero() public {
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidOwner.selector));
        new HybridAllocator(address(0), signer);
    }

    function test_constructor_skipSignerAssignmentIfAddressZero() public {
        HybridAllocator allocator_ = new HybridAllocator(owner, address(0));
        assertFalse(allocator_.signers(signer));
    }

    function test_checkAllocatorId() public view {
        assertEq(allocator.ALLOCATOR_ID(), _toAllocatorId(address(allocator)));
    }

    function test_checkNonce() public view {
        assertEq(allocator.nonces(), 0);
    }

    function test_checkOwner() public view {
        assertEq(allocator.owner(), owner);
    }

    function test_checkSigners(address attacker) public view {
        vm.assume(attacker != signer);

        assertTrue(allocator.signers(signer));
        assertFalse(allocator.signers(attacker));
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
            user, idsAndAmounts, _emptyAmounts(1), arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );
    }

    function test_prepareAllocation_returnsNonce_andDoesNotIncrement() public {
        uint256[2][] memory idsAndAmounts = _idsAndAmounts(address(usdc), defaultAmount);
        uint88 beforeNonces = allocator.nonces();
        // call prepare directly
        uint256 returnedNonce = allocator.prepareAllocation(
            user, idsAndAmounts, _emptyAmounts(1), arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );
        // HybridAllocator passes just the counter to AL.prepareAllocation, so nonce is: command | counter
        // (address(0) is used because HybridAllocator doesn't embed recipient in nonce pre-command)
        assertEq(returnedNonce, _composeNonceUint(ON_CHAIN_NONCE, address(0), uint256(beforeNonces) + 1));
        // storage not incremented yet
        assertEq(allocator.nonces(), beforeNonces);
    }

    function test_executeAllocation_success_viaCaller_singleERC20() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmounts(address(usdc), amount);
        // fund caller and approve
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // run flow in one tx
        vm.prank(user);
        allocationCaller.onChainAllocation(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '', 0
        );
        vm.snapshotGasLastCall('hybrid_execute_single');

        // nonces incremented
        assertEq(allocator.nonces(), 1);

        // derive claim hash and ensure isClaimAuthorized is true
        // HybridAllocator uses command | counter for nonce (no recipient embedded)
        Lock[] memory commitments = _idsAndAmountsToCommitments(idsAndAmounts);
        bytes32 claimHash = _toBatchCompactHash(
            BatchCompact({
                arbiter: arbiter,
                sponsor: user,
                nonce: _composeNonceUint(ON_CHAIN_NONCE, address(0), allocator.nonces()),
                expires: defaultExpiration,
                commitments: commitments
            })
        );
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    function test_executeAllocation_revert_InvalidPreparation() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmounts(address(usdc), amount);
        // fund caller and approve
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // todo=2: deposit+register without prepare -> expect AllocatorLib.InvalidPreparation
        vm.prank(user);
        vm.expectRevert(AllocatorLib.InvalidPreparation.selector);
        allocationCaller.onChainAllocation(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '', 2
        );
    }

    function test_executeAllocation_revert_InvalidRegistration() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmounts(address(usdc), amount);
        // fund caller and approve
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // Compute expected claim hash for the deposit-only path
        Lock[] memory commitments = _idsAndAmountsToCommitments(idsAndAmounts);
        // HybridAllocator uses command | counter for nonce (no recipient embedded)
        uint256 expectedNonce = _composeNonceUint(ON_CHAIN_NONCE, address(0), uint256(allocator.nonces()) + 1);
        bytes32 expectedClaimHash = _toBatchCompactHash(
            BatchCompact({
                arbiter: arbiter,
                sponsor: user,
                nonce: expectedNonce,
                expires: defaultExpiration,
                commitments: commitments
            })
        );

        // todo=1: deposit only, no register -> AllocatorLib.InvalidRegistration
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                AllocatorLib.InvalidRegistration.selector, user, expectedClaimHash, BATCH_COMPACT_TYPEHASH
            )
        );
        allocationCaller.onChainAllocation(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '', 1
        );
    }

    function test_executeAllocation_revert_InvalidBalanceChange_noDeposit() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmounts(address(usdc), amount);
        // give user prior ERC6909 balance so (oldBalance > 0)
        bytes12 lockTag = _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes);
        vm.startPrank(user);
        usdc.mint(user, amount);
        usdc.approve(address(compact), amount);
        compact.depositERC20(address(usdc), lockTag, amount, user);
        vm.stopPrank();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature('InvalidBalanceChange(uint256,uint256)', amount, amount));
        allocationCaller.onChainAllocation(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '', 3
        );
    }

    function test_executeAllocation_revert_InvalidPreparation_replaySameTx() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmounts(address(usdc), amount);
        // fund caller and approve
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        vm.prank(user);
        vm.expectRevert(AllocatorLib.InvalidPreparation.selector);
        allocationCaller.onChainAllocation(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '', 4
        );
    }

    function test_allocateAndRegister_revert_InvalidIds() public {
        vm.expectRevert(IHybridAllocator.InvalidIds.selector);
        allocator.allocateAndRegister(user, new uint256[2][](0), arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_allocateAndRegister_revert_InvalidAllocatorIdNative() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(this), /* wrong address */ address(0));
        idsAndAmounts[0][1] = defaultAmount;
        vm.expectRevert(
            abi.encodeWithSelector(
                IHybridAllocator.InvalidAllocatorId.selector, _toAllocatorId(address(this)), allocator.ALLOCATOR_ID()
            )
        );
        allocator.allocateAndRegister{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
    }

    function test_allocateAndRegister_revert_InvalidAllocatorIdERC20() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(this), /* wrong address */ address(usdc));
        idsAndAmounts[0][1] = defaultAmount;
        vm.expectRevert(
            abi.encodeWithSelector(
                IHybridAllocator.InvalidAllocatorId.selector, _toAllocatorId(address(this)), allocator.ALLOCATOR_ID()
            )
        );
        allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_allocateAndRegister_revert_InvalidValue() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0) /* use native */ );
        idsAndAmounts[0][1] = defaultAmount;
        vm.expectRevert(
            abi.encodeWithSelector(IHybridAllocator.InvalidValue.selector, defaultAmount + 1, defaultAmount)
        );
        allocator.allocateAndRegister{value: defaultAmount + 1}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
    }

    function test_allocateAndRegister_revert_zeroNativeTokensAmount() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidValue.selector, 0, 1));
        allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_allocateAndRegister_revert_zeroTokensAmount() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = 0;
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidDepositBalanceChange.selector));
        allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_allocateAndRegister_revert_tokensNotProvided() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;
        vm.expectRevert(abi.encodeWithSignature('TransferFromFailed()'));
        allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_allocateAndRegister_revert_invalidTokenOrder() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = 0;

        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[1][1] = 0;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);

        vm.expectRevert(); // Will revert when trying to approve tokens of address(0)
        allocator.allocateAndRegister{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
    }

    function test_allocateAndRegister_success_nativeToken() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0) /* use native */ );
        idsAndAmounts[0][1] = defaultAmount;
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('allocateAndRegister_nativeToken');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(registeredAmounts.length, 1);
        assertEq(address(compact).balance, defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, _composeNonceUint(ON_CHAIN_NONCE, address(0), 1));
    }

    function test_allocateAndRegister_success_erc20Token() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) =
            allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('allocateAndRegister_erc20Token');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, _composeNonceUint(ON_CHAIN_NONCE, address(0), 1));
    }

    function test_allocateAndRegister_success_nativeTokenWithEmptyAmountInput() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0) /* use native */ );
        idsAndAmounts[0][1] = 0;
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('allocateAndRegister_nativeToken_emptyAmountInput');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(address(compact).balance, defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, _composeNonceUint(ON_CHAIN_NONCE, address(0), 1));
    }

    function test_allocateAndRegister_success_erc20TokenWithEmptyAmountInput() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = 0;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) =
            allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('allocateAndRegister_erc20Token_emptyAmountInput');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(registeredAmounts.length, 1);
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, _composeNonceUint(ON_CHAIN_NONCE, address(0), 1));
    }

    function test_allocateAndRegister_success_multipleTokens() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[1][1] = 0;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('allocateAndRegister_multipleTokens');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(registeredAmounts[1], defaultAmount);
        assertEq(registeredAmounts.length, 2);
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(address(compact).balance, defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[1][0]), defaultAmount);
        assertEq(nonce, _composeNonceUint(ON_CHAIN_NONCE, address(0), 1));
    }

    function test_allocateAndRegister_checkNonceIncrements_nativeToken() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        assertEq(allocator.nonces(), 0);

        // Register first claim
        allocator.allocateAndRegister{value: 5e17}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
        assertEq(allocator.nonces(), 1);

        // Register second claim
        (bytes32 claimHash, uint256[] memory registeredAmounts,) = allocator.allocateAndRegister{value: 5e17}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
        vm.snapshotGasLastCall('allocateAndRegister_second_nativeToken');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], 5e17);
        assertEq(registeredAmounts.length, 1);

        assertEq(allocator.nonces(), 2);
    }

    function test_allocateAndRegister_checkNonceIncrements_erc20Token() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = 0;

        assertEq(allocator.nonces(), 0);

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount / 2);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount / 2);

        // Register first claim
        allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        assertEq(allocator.nonces(), 1);

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount / 2);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount / 2);

        // Register second claim
        (bytes32 claimHash, uint256[] memory registeredAmounts,) =
            allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('allocateAndRegister_second_erc20Token');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount / 2);
        assertEq(registeredAmounts.length, 1);
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);

        assertEq(allocator.nonces(), 2);
    }

    function test_allocateAndRegister_checkClaimHashNoWitness() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, registeredAmounts, nonce);

        bytes32 createdHash = _toBatchCompactHash(batch);
        assertEq(createdHash, claimHash);
        assertTrue(allocator.isClaimAuthorized(createdHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    function test_allocateAndRegister_checkClaimHashWitness() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH_WITH_WITNESS, witness);
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, registeredAmounts, nonce);
        bytes32 createdHash = _toBatchCompactHashWithWitness(BATCH_COMPACT_TYPEHASH_WITH_WITNESS, batch, witness);
        assertEq(createdHash, claimHash);
        assertTrue(allocator.isClaimAuthorized(createdHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    function test_allocateAndRegister_success_emptyRecipientBecomesCaller() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);

        vm.prank(user);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister(
            address(0), /* allocate for an empty recipient */
            idsAndAmounts,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            ''
        );

        // Ensure the allocation happened for the caller (user), not address(0)
        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        // HybridAllocator nonce format: command | counter (no address embedded)
        assertEq(nonce, _composeNonceUint(ON_CHAIN_NONCE, address(0), 1));
    }

    function test_allocateAndRegister_slot() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        (bytes32 claimHash,,) = allocator.allocateAndRegister{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH_WITH_WITNESS, witness
        );

        bytes32 claimSlot = keccak256(abi.encode(claimHash, 0x00));
        bytes32 claimSlotData = vm.load(address(allocator), claimSlot);
        assertEq(claimSlotData, bytes32(uint256(1)));
    }

    function test_isClaimAuthorized_unauthorized() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, registeredAmounts, nonce);

        // Use the same batchCompact, but add a witness
        bytes32 falseHash = _toBatchCompactHashWithWitness(BATCH_COMPACT_TYPEHASH_WITH_WITNESS, batch, bytes32(0));
        assertNotEq(falseHash, claimHash);
        assertFalse(allocator.isClaimAuthorized(falseHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    function test_isClaimAuthorized_signerZeroAddress() public {
        // Create an arbitrary claim hash that has not been registered.
        bytes32 claimHash = keccak256('invalid');
        assertEq(ecrecover(claimHash, 0, bytes32(0), bytes32(0)), address(0));

        // Craft a 65-byte signature that will make ecrecover return the zero address:
        // r = 0, s = 0, v = 0 (v not 27/28).
        bytes memory invalidSignature = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        // Forcing address(0) as signer
        // Storage layout: slot 0 = claims mapping, slot 1 = nonces + owner (packed), slot 2 = signers mapping
        uint256 signersSlot = 0x02;
        vm.store(address(allocator), keccak256(abi.encode(address(0), signersSlot)), bytes32(uint256(1)));

        assertTrue(allocator.signers(address(0)));

        assertFalse(
            allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), invalidSignature)
        );
    }

    function test_isClaimAuthorized_withSigner_bytes64() public view {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, 1);

        bytes32 claimHash = _toBatchCompactHashWithWitness(BATCH_COMPACT_TYPEHASH_WITH_WITNESS, batch, witness);
        bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());
        (bytes32 r, bytes32 vs) = vm.signCompact(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, vs);
        assertEq(signature.length, 64);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, user, 1, defaultExpiration, idsAndAmounts, signature)
        );
    }

    function test_isClaimAuthorized_withSigner_bytes65() public view {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, 1);

        bytes32 claimHash;
        bytes memory signature;
        {
            claimHash = _toBatchCompactHashWithWitness(BATCH_COMPACT_TYPEHASH_WITH_WITNESS, batch, witness);
            bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
            signature = abi.encodePacked(r, s, v);
        }
        assertEq(signature.length, 65);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, user, 1, defaultExpiration, idsAndAmounts, signature)
        );
    }

    function test_isClaimAuthorized_invalidSignature() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, 1);

        bytes32 claimHash = _toBatchCompactHashWithWitness(BATCH_COMPACT_TYPEHASH_WITH_WITNESS, batch, witness);
        bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());

        bytes memory signature;
        {
            (, uint256 attackerPK) = makeAddrAndKey('attacker');
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPK, digest);
            signature = abi.encodePacked(r, s, v);
            assertEq(signature.length, 65);
        }
        assertFalse(
            allocator.isClaimAuthorized(claimHash, arbiter, user, 1, defaultExpiration, idsAndAmounts, signature)
        );
    }

    function test_attest_revert_InvalidCaller() public {
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        address target = makeAddr('target');

        // attest should only be callable by TheCompact
        vm.expectRevert(
            abi.encodeWithSelector(IHybridAllocator.InvalidCaller.selector, address(this), address(compact))
        );
        allocator.attest(signer, user, target, id, defaultAmount);
    }

    function test_attest_revert_InsufficientAttestationAmount() public {
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        address target = makeAddr('target');

        assertEq(usdc.balanceOf(user), 10 ether); // setUp mints 10 ether
        vm.startPrank(user);
        usdc.approve(address(compact), defaultAmount);
        compact.depositERC20(address(usdc), bytes12(bytes32(id)), defaultAmount, user);

        // Transfer without prior authorizeAttestation should fail with InsufficientAttestationAmount
        vm.expectRevert(
            abi.encodeWithSelector(IHybridAllocator.InsufficientAttestationAmount.selector, 0, defaultAmount),
            address(allocator)
        );
        compact.transfer(target, id, defaultAmount);
        vm.stopPrank();
    }

    function test_authorizeClaim_revert_invalidCaller(address attacker) public {
        vm.assume(attacker != address(compact));
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);
        assertEq(address(allocator).balance, 0);

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        vm.prank(user);
        (bytes32 claimHash,,) = allocator.allocateAndRegister{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH_WITH_WITNESS, witness
        );

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidCaller.selector, attacker, address(compact)));
        allocator.authorizeClaim(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), '');
    }

    function test_revert_authorizeClaim_InvalidSignature(uint88 freeNonce) public {
        // Compose the full nonce with OFF_CHAIN_NONCE command + sponsor address
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce);

        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[1][1] = defaultAmount;

        // Approve tokens
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        bytes32 claimHash = _toBatchCompactHashWithWitness(
            BATCH_COMPACT_TYPEHASH_WITH_WITNESS,
            BatchCompact({
                arbiter: arbiter,
                sponsor: user,
                nonce: nonce,
                expires: defaultExpiration,
                commitments: _idsAndAmountsToCommitments(idsAndAmounts)
            }),
            witness
        );

        bytes32[2][] memory claimHashesAndTypehashes = new bytes32[2][](1);
        claimHashesAndTypehashes[0][0] = claimHash;
        claimHashesAndTypehashes[0][1] = BATCH_COMPACT_TYPEHASH_WITH_WITNESS;

        // Deposit and register
        vm.prank(user);
        compact.batchDepositAndRegisterMultiple{value: defaultAmount}(idsAndAmounts, claimHashesAndTypehashes);

        // Off chain signing the claim
        bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());
        (address attacker, uint256 attackerPK) = makeAddrAndKey('attacker');
        (bytes32 r, bytes32 vs) = vm.signCompact(attackerPK, digest);
        bytes memory allocatorData = abi.encodePacked(r, vs);

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);
        {
            Component[] memory portions = new Component[](1);
            portions[0] = Component({
                claimant: uint256(bytes32(abi.encodePacked(bytes12(0), attacker))), // indicating a withdrawal
                amount: defaultAmount
            });

            claims[0] =
                BatchClaimComponent({id: idsAndAmounts[0][0], allocatedAmount: defaultAmount, portions: portions});
            claims[1] =
                BatchClaimComponent({id: idsAndAmounts[1][0], allocatedAmount: defaultAmount, portions: portions});
        }

        BatchClaim memory claim = BatchClaim({
            allocatorData: allocatorData,
            sponsorSignature: '',
            sponsor: user,
            nonce: nonce,
            expires: defaultExpiration,
            witness: witness,
            witnessTypestring: WITNESS_STRING,
            claims: claims
        });

        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSignature.selector));
        compact.batchClaim(claim);
    }

    function test_authorizeClaim_revert_oldSignatureAfterFork(uint88 freeNonce) public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[1][1] = defaultAmount;

        // Approve tokens
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        // Format nonce with OFF_CHAIN_NONCE command and user as sponsor
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce);

        bytes32 claimHash = _toBatchCompactHashWithWitness(
            BATCH_COMPACT_TYPEHASH_WITH_WITNESS,
            BatchCompact({
                arbiter: arbiter,
                sponsor: user,
                nonce: nonce,
                expires: defaultExpiration,
                commitments: _idsAndAmountsToCommitments(idsAndAmounts)
            }),
            witness
        );

        bytes32[2][] memory claimHashesAndTypehashes = new bytes32[2][](1);
        claimHashesAndTypehashes[0][0] = claimHash;
        claimHashesAndTypehashes[0][1] = BATCH_COMPACT_TYPEHASH_WITH_WITNESS;

        // Deposit and register
        vm.prank(user);
        compact.batchDepositAndRegisterMultiple{value: defaultAmount}(idsAndAmounts, claimHashesAndTypehashes);

        // Off chain signing the claim
        bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());
        (bytes32 r, bytes32 vs) = vm.signCompact(signerPrivateKey, digest);
        bytes memory allocatorData = abi.encodePacked(r, vs);

        address target = makeAddr('target');

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);
        {
            Component[] memory portions = new Component[](1);
            portions[0] = Component({
                claimant: uint256(bytes32(abi.encodePacked(bytes12(0), target))), // indicating a withdrawal
                amount: defaultAmount
            });

            claims[0] =
                BatchClaimComponent({id: idsAndAmounts[0][0], allocatedAmount: defaultAmount, portions: portions});
            claims[1] =
                BatchClaimComponent({id: idsAndAmounts[1][0], allocatedAmount: defaultAmount, portions: portions});
        }

        BatchClaim memory claim = BatchClaim({
            allocatorData: allocatorData,
            sponsorSignature: '',
            sponsor: user,
            nonce: nonce,
            expires: defaultExpiration,
            witness: witness,
            witnessTypestring: WITNESS_STRING,
            claims: claims
        });

        uint256 snap = vm.snapshot();
        assertEq(block.chainid, 31_337);

        vm.prank(arbiter);
        compact.batchClaim(claim);
        // Call did not revert

        vm.revertTo(snap);
        vm.chainId(1);
        assertEq(block.chainid, 1);

        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSignature.selector));
        compact.batchClaim(claim);
    }

    function test_authorizeClaim_success_onChain() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[1][1] = 0;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);
        assertEq(address(allocator).balance, 0);

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        vm.prank(user);
        (bytes32 claimHash,, uint256 nonce) = allocator.allocateAndRegister{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH_WITH_WITNESS, witness
        );

        address target = makeAddr('target');

        bytes32 returnedClaimHash;
        {
            Component[] memory portions = new Component[](1);
            portions[0] = Component({
                claimant: uint256(bytes32(abi.encodePacked(bytes12(0), target))), // indicating a withdrawal
                amount: defaultAmount
            });

            BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);
            claims[0] =
                BatchClaimComponent({id: idsAndAmounts[0][0], allocatedAmount: defaultAmount, portions: portions});
            claims[1] =
                BatchClaimComponent({id: idsAndAmounts[1][0], allocatedAmount: defaultAmount, portions: portions});

            BatchClaim memory claim = BatchClaim({
                allocatorData: '',
                sponsorSignature: '',
                sponsor: user,
                nonce: nonce,
                expires: defaultExpiration,
                witness: witness,
                witnessTypestring: WITNESS_STRING,
                claims: claims
            });
            vm.prank(arbiter);
            returnedClaimHash = compact.batchClaim(claim);
            assertEq(returnedClaimHash, claimHash);
        }

        // User started with 10 ether ETH and 10 ether USDC, provided defaultAmount of each
        assertEq(usdc.balanceOf(address(compact)), 0, 'compact usdc balance should be 0');
        assertEq(
            usdc.balanceOf(address(user)),
            10 ether - defaultAmount,
            'user usdc balance should be 10 ether - defaultAmount'
        );
        assertEq(usdc.balanceOf(address(target)), defaultAmount, 'target usdc balance should be defaultAmount');
        assertEq(address(compact).balance, 0, 'compact balance should be 0');
        assertEq(address(user).balance, 10 ether - defaultAmount, 'user balance should be 10 ether - defaultAmount');
        assertEq(address(target).balance, defaultAmount, 'target balance should be defaultAmount');
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), 0, 'user eth compact balance of 0 should be 0');
        assertEq(
            compact.balanceOf(address(target), idsAndAmounts[0][0]), 0, 'target eth compact balance of 0 should be 0'
        );
        assertEq(compact.balanceOf(address(user), idsAndAmounts[1][0]), 0, 'user usdc compact balance of 0 should be 0');
        assertEq(
            compact.balanceOf(address(target), idsAndAmounts[1][0]), 0, 'target usdc compact balance of 0 should be 0'
        );
    }

    function test_authorizeClaim_success_offChain(uint88 freeNonce) public {
        // Compose the full nonce with OFF_CHAIN_NONCE command + sponsor address
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce);

        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[1][1] = defaultAmount;

        // Approve tokens
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        bytes32 claimHash = _toBatchCompactHashWithWitness(
            BATCH_COMPACT_TYPEHASH_WITH_WITNESS,
            BatchCompact({
                arbiter: arbiter,
                sponsor: user,
                nonce: nonce,
                expires: defaultExpiration,
                commitments: _idsAndAmountsToCommitments(idsAndAmounts)
            }),
            witness
        );

        bytes32[2][] memory claimHashesAndTypehashes = new bytes32[2][](1);
        claimHashesAndTypehashes[0][0] = claimHash;
        claimHashesAndTypehashes[0][1] = BATCH_COMPACT_TYPEHASH_WITH_WITNESS;

        // Deposit and register
        vm.prank(user);
        compact.batchDepositAndRegisterMultiple{value: defaultAmount}(idsAndAmounts, claimHashesAndTypehashes);

        // Off chain signing the claim
        bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());
        (bytes32 r, bytes32 vs) = vm.signCompact(signerPrivateKey, digest);
        bytes memory allocatorData = abi.encodePacked(r, vs);

        address target = makeAddr('target');

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);
        {
            Component[] memory portions = new Component[](1);
            portions[0] = Component({
                claimant: uint256(bytes32(abi.encodePacked(bytes12(0), target))), // indicating a withdrawal
                amount: defaultAmount
            });

            claims[0] =
                BatchClaimComponent({id: idsAndAmounts[0][0], allocatedAmount: defaultAmount, portions: portions});
            claims[1] =
                BatchClaimComponent({id: idsAndAmounts[1][0], allocatedAmount: defaultAmount, portions: portions});
        }

        BatchClaim memory claim = BatchClaim({
            allocatorData: allocatorData,
            sponsorSignature: '',
            sponsor: user,
            nonce: nonce,
            expires: defaultExpiration,
            witness: witness,
            witnessTypestring: WITNESS_STRING,
            claims: claims
        });

        vm.prank(arbiter);
        bytes32 returnedClaimHash = compact.batchClaim(claim);
        assertEq(returnedClaimHash, claimHash);

        assertEq(usdc.balanceOf(address(compact)), 0, 'compact usdc balance should be 0');
        // User started with 10 ether USDC (setUp), deposited defaultAmount, so has 10 ether - defaultAmount remaining
        assertEq(
            usdc.balanceOf(address(user)),
            10 ether - defaultAmount,
            'user usdc balance should be 10 ether - defaultAmount'
        );
        assertEq(usdc.balanceOf(address(target)), defaultAmount, 'target usdc balance should be defaultAmount');
        assertEq(address(compact).balance, 0, 'compact balance should be 0');
        // User started with 10 ether ETH (setUp), deposited defaultAmount, so has 10 ether - defaultAmount remaining
        assertEq(address(user).balance, 10 ether - defaultAmount, 'user balance should be 10 ether - defaultAmount');
        assertEq(address(target).balance, defaultAmount, 'target balance should be defaultAmount');
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), 0, 'user eth compact balance of 0 should be 0');
        assertEq(
            compact.balanceOf(address(target), idsAndAmounts[0][0]), 0, 'target eth compact balance of 0 should be 0'
        );
        assertEq(compact.balanceOf(address(user), idsAndAmounts[1][0]), 0, 'user usdc compact balance of 0 should be 0');
        assertEq(
            compact.balanceOf(address(target), idsAndAmounts[1][0]), 0, 'target usdc compact balance of 0 should be 0'
        );
    }

    function test_authorizeClaim_registrationDeleted() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        vm.prank(user);
        (bytes32 claimHash,, uint256 nonce) = allocator.allocateAndRegister{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );

        bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());
        (bytes32 r, bytes32 vs) = vm.signCompact(userPrivateKey, digest);
        bytes memory sponsorSignature = abi.encodePacked(r, vs);

        address target = makeAddr('target');

        Component[] memory portions = new Component[](1);
        portions[0] = Component({
            claimant: uint256(bytes32(abi.encodePacked(bytes12(0), target))), // indicating a withdrawal
            amount: defaultAmount
        });

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        claims[0] = BatchClaimComponent({id: idsAndAmounts[0][0], allocatedAmount: defaultAmount, portions: portions});

        BatchClaim memory claim = BatchClaim({
            allocatorData: '',
            sponsorSignature: sponsorSignature,
            sponsor: user,
            nonce: nonce,
            expires: defaultExpiration,
            witness: '',
            witnessTypestring: '',
            claims: claims
        });

        vm.prank(arbiter);
        bytes32 returnedClaimHash = compact.batchClaim(claim);
        assertEq(returnedClaimHash, claimHash);

        assertFalse(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    function test_addSigner_revert_CallerNotOwner(address attacker) public {
        vm.assume(attacker != address(0));
        vm.assume(attacker != owner);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.CallerNotOwner.selector));
        allocator.addSigner(attacker);
        assertFalse(allocator.signers(attacker));
    }

    function test_addSigner_revert_signerIsZero() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSigner.selector));
        allocator.addSigner(address(0));
        assertFalse(allocator.signers(address(0)));
    }

    function test_addSigner_success(address newSigner) public {
        vm.assume(newSigner != signer);
        vm.assume(newSigner != address(0));
        vm.prank(owner);
        allocator.addSigner(newSigner);
        assertTrue(allocator.signers(newSigner));
        assertTrue(allocator.signers(signer));
    }

    function test_removeSigner_revert_CallerNotOwner(address attacker) public {
        vm.assume(attacker != owner);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.CallerNotOwner.selector));
        allocator.removeSigner(signer);
        assertTrue(allocator.signers(signer));
    }

    function test_removeSigner_revert_InvalidSigner(address attacker) public {
        vm.assume(attacker != signer);
        vm.assume(attacker != address(this));
        vm.prank(owner);
        allocator.addSigner(address(this));
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSigner.selector));
        allocator.removeSigner(attacker);
        assertTrue(allocator.signers(address(this)));
        assertTrue(allocator.signers(signer));
    }

    function test_removeSigner_success(address newSigner) public {
        vm.assume(newSigner != signer);
        vm.assume(newSigner != address(0));
        vm.prank(owner);
        allocator.addSigner(newSigner);
        vm.prank(owner);
        allocator.removeSigner(signer);
        assertFalse(allocator.signers(signer));
        assertTrue(allocator.signers(newSigner));
    }

    function test_removeSigner_success_deleteSelf(address newSigner) public {
        vm.assume(newSigner != signer);
        vm.assume(newSigner != address(0));
        vm.prank(owner);
        allocator.addSigner(newSigner);
        vm.prank(owner);
        allocator.removeSigner(newSigner);
        assertTrue(allocator.signers(signer));
        assertFalse(allocator.signers(newSigner));
    }

    function test_replaceSigner_revert_CallerNotOwner(address attacker) public {
        vm.assume(attacker != owner);
        address newSigner = makeAddr('newSigner');
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.CallerNotOwner.selector));
        allocator.replaceSigner(signer, newSigner);
        assertFalse(allocator.signers(newSigner));
    }

    function test_replaceSigner_revert_signerIsZero() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSigner.selector));
        allocator.replaceSigner(signer, address(0));
        assertFalse(allocator.signers(address(0)));
    }

    function test_replaceSigner_revert_sameSigners() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSigner.selector));
        allocator.replaceSigner(signer, signer);
        assertTrue(allocator.signers(signer));
    }

    function test_replaceSigner_success_twoStep(address newSigner) public {
        vm.assume(newSigner != signer);
        vm.assume(newSigner != address(0));
        vm.prank(owner);
        allocator.replaceSigner(signer, newSigner);
        // Immediate replacement - no two step anymore
        assertFalse(allocator.signers(signer));
        assertTrue(allocator.signers(newSigner));
    }

    function test_replaceSigner(address newSigner, address newSigner2) public {
        vm.assume(newSigner != signer);
        vm.assume(newSigner != address(0));
        vm.assume(newSigner2 != signer);
        vm.assume(newSigner2 != address(0));
        vm.assume(newSigner2 != newSigner);

        vm.prank(owner);
        allocator.replaceSigner(signer, newSigner);
        // Now newSigner is the signer
        assertFalse(allocator.signers(signer));
        assertTrue(allocator.signers(newSigner));

        // Replace newSigner with newSigner2
        vm.prank(owner);
        allocator.replaceSigner(newSigner, newSigner2);

        assertFalse(allocator.signers(signer));
        assertFalse(allocator.signers(newSigner));
        assertTrue(allocator.signers(newSigner2));
    }

    function test_proposeOwnerReplacement_revert_CallerNotOwner(address attacker) public {
        vm.assume(attacker != owner);
        address newOwner = makeAddr('newOwner');
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.CallerNotOwner.selector));
        allocator.proposeOwnerReplacement(newOwner);
    }

    function test_proposeOwnerReplacement_revert_zeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidOwner.selector));
        allocator.proposeOwnerReplacement(address(0));
    }

    function test_acceptOwnerReplacement_revert_notPendingOwner(address attacker) public {
        vm.assume(attacker != owner);
        address newOwner = makeAddr('newOwner');
        vm.assume(attacker != newOwner);

        // First propose a new owner
        vm.prank(owner);
        allocator.proposeOwnerReplacement(newOwner);

        // Try to accept from wrong address
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidOwner.selector));
        allocator.acceptOwnerReplacement();
    }

    function test_ownerReplacement_success() public {
        address newOwner = makeAddr('newOwner');

        // Propose new owner
        vm.prank(owner);
        allocator.proposeOwnerReplacement(newOwner);
        assertEq(allocator.owner(), owner);

        // Accept as new owner
        vm.prank(newOwner);
        allocator.acceptOwnerReplacement();
        assertEq(allocator.owner(), newOwner);

        // New owner can add signers
        address newSigner = makeAddr('anotherSigner');
        vm.prank(newOwner);
        allocator.addSigner(newSigner);
        assertTrue(allocator.signers(newSigner));

        // Old owner cannot add signers
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.CallerNotOwner.selector));
        allocator.addSigner(makeAddr('yetAnotherSigner'));
    }

    function test_constructor_allowsPreRegisteredAllocator_create2() public {
        HybridAllocatorFactory factory = new HybridAllocatorFactory();

        bytes32 salt = keccak256('hybrid-allocator-pre-registered');
        // initCode must match what the factory deploys: creationCode + abi.encode(owner, signer)
        bytes memory initCode = abi.encodePacked(type(HybridAllocator).creationCode, abi.encode(owner, signer));
        bytes32 initCodeHash = keccak256(initCode);

        address expected =
            address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(factory), salt, initCodeHash)))));

        bytes memory proof = abi.encodePacked(bytes1(0xff), address(factory), salt, initCodeHash);

        uint96 preId = compact.__registerAllocator(expected, proof);
        assertEq(_toAllocatorId(expected), preId);

        address deployed = HybridAllocatorFactory(address(factory)).deploy(salt, owner, signer);
        assertEq(deployed, expected);

        HybridAllocator newAllocator = HybridAllocator(deployed);
        assertEq(newAllocator.ALLOCATOR_ID(), _toAllocatorId(deployed));
    }

    /* ====================================================================== */
    /*                   Tests for permit2Allocation                          */
    /* ====================================================================== */

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
        bytes memory signature = _createPermit2Signature(permitted, details, claimHash, userPrivateKey);

        // Execute
        Lock[] memory commitments = allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            _emptyAmounts(1),
            details,
            claimHash,
            '',
            bytes32(0),
            signature,
            ''
        );
        vm.snapshotGasLastCall('hybrid_permit2Allocation_singleERC20');

        // Verify commitments
        assertEq(commitments.length, 1);
        assertEq(commitments[0].lockTag, lockTag);
        assertEq(commitments[0].token, address(usdc));
        assertEq(commitments[0].amount, defaultAmount);

        // Verify claim is authorized
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));

        // Verify tokens are in compact
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(compact.balanceOf(user, ids[0]), defaultAmount);
    }

    function test_permit2Allocation_singleERC20_withWitness() public {
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

        // Create a witness value - using a simple Mandate(uint256 witness) struct
        // The witness is the hash of the witness struct: keccak256(abi.encode(WITNESS_TYPEHASH, witnessValue))
        uint256 witnessValue = 12_345;
        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, witnessValue));

        // Compute claimHash WITH witness using BATCH_COMPACT_TYPEHASH_WITH_WITNESS
        bytes32 claimHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH_WITH_WITNESS,
                arbiter,
                user,
                nonce,
                defaultExpiration,
                keccak256(abi.encodePacked(commitmentHashes)),
                witness
            )
        );

        // Create Permit2 signature using the WITH_WITNESS helper
        // This uses PERMIT_BATCH_WITNESS_WITH_MANDATE_TYPEHASH since we have a witness
        bytes memory signature = _createPermit2SignatureWithWitness(permitted, details, claimHash, userPrivateKey);

        // Execute with witness typestring
        // Note: The witness parameter should be just the inner content (e.g., "uint256 witness"),
        // not the full struct definition, as TheCompact wraps it in "Mandate(...)"
        Lock[] memory commitments = allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            _emptyAmounts(1),
            details,
            claimHash,
            WITNESS_STRING,
            witness,
            signature,
            ''
        );
        vm.snapshotGasLastCall('hybrid_permit2Allocation_singleERC20_withWitness');

        // Verify commitments
        assertEq(commitments.length, 1);
        assertEq(commitments[0].lockTag, lockTag);
        assertEq(commitments[0].token, address(usdc));
        assertEq(commitments[0].amount, defaultAmount);

        // Verify claim is authorized
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));

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
        bytes memory signature = _createPermit2Signature(permitted, details, claimHash, userPrivateKey);

        // Execute
        Lock[] memory commitments = allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            _emptyAmounts(2),
            details,
            claimHash,
            '',
            bytes32(0),
            signature,
            ''
        );
        vm.snapshotGasLastCall('hybrid_permit2Allocation_multipleERC20');

        // Verify commitments
        assertEq(commitments.length, 2);

        // Verify claim is authorized
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));

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

        bytes memory signature = _createPermit2Signature(permitted, details, claimHash, userPrivateKey);

        // Should revert with UnauthorizedNonce because command is not PERMIT2_NONCE
        vm.expectRevert(abi.encodeWithSelector(AllocatorLib.UnauthorizedNonce.selector, bytes1(0x01), user));
        allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            _emptyAmounts(1),
            details,
            claimHash,
            '',
            bytes32(0),
            signature,
            ''
        );
    }

    function test_permit2Allocation_revert_invalidNonceSponsor() public {
        bytes12 lockTag = _getLockTag();
        address wrongSponsor = makeAddr('wrongSponsor');
        // Use correct command but wrong sponsor address in nonce
        uint256 invalidNonce = _createPermit2Nonce(wrongSponsor, 1);

        // Prepare token permissions
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), defaultAmount);

        // Prepare deposit details with nonce that has wrong sponsor
        DepositDetails memory details = _createDepositDetails(invalidNonce, defaultExpiration, lockTag);

        bytes32 claimHash = bytes32(uint256(1)); // dummy claim hash

        // Signature won't matter because nonce verification happens first
        bytes memory signature = new bytes(64);

        // Should revert because sponsor in nonce doesn't match depositor
        vm.expectRevert(abi.encodeWithSelector(AllocatorLib.UnauthorizedNonce.selector, bytes1(0x03), wrongSponsor));
        allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            _emptyAmounts(1),
            details,
            claimHash,
            '',
            bytes32(0),
            signature,
            ''
        );
    }

    function test_permit2Allocation_emitsAllocatedEvent() public {
        bytes12 lockTag = _getLockTag();
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);

        // Prepare token permissions
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), defaultAmount);

        // Prepare deposit details
        DepositDetails memory details = _createDepositDetails(nonce, defaultExpiration, lockTag);

        // Compute ids and claimHash
        uint256[] memory ids = new uint256[](1);
        ids[0] = AllocatorLib.toId(lockTag, address(usdc));
        bytes32[] memory commitmentHashes = new bytes32[](1);
        commitmentHashes[0] = _computeCommitmentHash(ids[0], defaultAmount);

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

        bytes memory signature = _createPermit2Signature(permitted, details, claimHash, userPrivateKey);

        // Expect Allocated event
        Lock[] memory expectedCommitments = new Lock[](1);
        expectedCommitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: defaultAmount});

        vm.expectEmit(true, true, true, true);
        emit IOnChainAllocation.Allocated(user, expectedCommitments, nonce, defaultExpiration, claimHash);

        allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            _emptyAmounts(1),
            details,
            claimHash,
            '',
            bytes32(0),
            signature,
            ''
        );
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
        bytes memory signature = _createPermit2Signature(permitted, details, claimHash, userPrivateKey);

        // Execute permit2Allocation
        allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            _emptyAmounts(1),
            details,
            claimHash,
            '',
            bytes32(0),
            signature,
            ''
        );

        // Verify claim is authorized
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));

        // Now execute the claim
        address recipient = makeAddr('recipient');
        Component[] memory portions = new Component[](1);
        portions[0] =
            Component({claimant: uint256(bytes32(abi.encodePacked(bytes12(0), recipient))), amount: defaultAmount});

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
        assertEq(usdc.balanceOf(recipient), defaultAmount);
        assertEq(usdc.balanceOf(address(compact)), 0);

        // Verify claim is no longer authorized (deleted after execution)
        assertFalse(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    /* --------------------------------------------------------------------- */
    /*                   additionalCommitmentAmounts Tests                    */
    /* --------------------------------------------------------------------- */

    string constant HYBRID_ALLOCATION_CONTEXT_TYPESTRING =
        'HybridAllocationContext(bytes32 claimHash,Lock[] additionalCommitments)Lock(bytes12 lockTag,address token,uint256 amount)';
    bytes32 constant HYBRID_ALLOCATION_CONTEXT_TYPEHASH = keccak256(bytes(HYBRID_ALLOCATION_CONTEXT_TYPESTRING));

    /// @dev Creates a signature for HybridAllocationContext
    function _createContextSignature(
        bytes32 claimHash,
        Lock[] memory commitments,
        uint256[] memory additionalCommitmentAmounts,
        uint256 signerPk,
        bool compactSignature
    ) internal view returns (bytes memory) {
        // Create commitment hashes using additionalCommitmentAmounts instead of commitment.amount
        bytes32[] memory commitmentHashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; i++) {
            commitmentHashes[i] = keccak256(
                abi.encode(LOCK_TYPEHASH, commitments[i].lockTag, commitments[i].token, additionalCommitmentAmounts[i])
            );
        }

        bytes32 commitmentsHash = keccak256(abi.encodePacked(commitmentHashes));
        bytes32 hybridAllocationHash =
            keccak256(abi.encode(HYBRID_ALLOCATION_CONTEXT_TYPEHASH, claimHash, commitmentsHash));

        bytes32 domainSeparator = compact.DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), domainSeparator, hybridAllocationHash));

        if (compactSignature) {
            (bytes32 r, bytes32 vs) = vm.signCompact(signerPk, digest);
            return abi.encodePacked(r, vs);
        } else {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
            return abi.encodePacked(r, s, v);
        }
    }

    /// @dev Encodes a HybridAllocationContext for use in prepareAllocation/executeAllocation
    function _encodeHybridAllocationContext(uint256 nonce, bytes memory signature)
        internal
        pure
        returns (bytes memory)
    {
        IHybridAllocator.HybridAllocationContext memory context =
            IHybridAllocator.HybridAllocationContext({nonce: nonce, signature: signature});
        return abi.encode(context);
    }

    /// @notice Test permit2Allocation with additionalCommitmentAmounts using existing balance
    function test_permit2Allocation_withAdditionalCommitments() public {
        uint256 existingBalance = defaultAmount;
        uint256 newDeposit = defaultAmount;
        uint256 additionalCommitment = existingBalance / 2;
        uint256 totalCommitment = newDeposit + additionalCommitment;

        // First, deposit tokens directly to the user (existing balance)
        usdc.mint(user, existingBalance);
        vm.startPrank(user);
        usdc.approve(address(compact), existingBalance);
        bytes12 lockTag = _getLockTag();
        uint256 id = compact.depositERC20(address(usdc), lockTag, existingBalance, user);
        vm.stopPrank();

        // Verify existing balance
        assertEq(compact.balanceOf(user, id), existingBalance);

        // Now do a permit2 allocation with additional commitment from existing balance
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);

        // Mint additional tokens for permit2 deposit
        usdc.mint(user, newDeposit);

        // Prepare token permissions for permit2
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), newDeposit);

        // Prepare deposit details
        DepositDetails memory details = _createDepositDetails(nonce, defaultExpiration, lockTag);

        // Compute claimHash with total commitment amount
        bytes32[] memory commitmentHashes = new bytes32[](1);
        commitmentHashes[0] = _computeCommitmentHash(id, totalCommitment);

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
        bytes memory permit2Signature = _createPermit2Signature(permitted, details, claimHash, userPrivateKey);

        // Create additional commitment amounts array
        uint256[] memory additionalCommitmentAmounts = new uint256[](1);
        additionalCommitmentAmounts[0] = additionalCommitment;

        // Create the commitments array for context signature
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: totalCommitment});

        // Create 64 bytes compact signature
        uint256 snap = vm.snapshot();
        // Create allocator signature for the additional commitments (context)
        bytes memory contextSignature =
            _createContextSignature(claimHash, commitments, additionalCommitmentAmounts, signerPrivateKey, true); // true creating 64 bytes signature

        // Execute permit2Allocation with the context signature
        allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            additionalCommitmentAmounts,
            details,
            claimHash,
            '',
            bytes32(0),
            permit2Signature,
            contextSignature
        );

        // Verify claim is authorized
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));

        // Verify user has total balance (existing + new deposit)
        assertEq(compact.balanceOf(user, id), existingBalance + newDeposit);

        // Verify the registration on the compact
        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));

        // Revert and check with 65 byte signature
        vm.revertTo(snap);

        contextSignature =
            _createContextSignature(claimHash, commitments, additionalCommitmentAmounts, signerPrivateKey, false); // false creating 65 bytes signature

        // Execute permit2Allocation with the context signature
        allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            additionalCommitmentAmounts,
            details,
            claimHash,
            '',
            bytes32(0),
            permit2Signature,
            contextSignature
        );

        // Verify claim is authorized
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));

        // Verify user has total balance (existing + new deposit)
        assertEq(compact.balanceOf(user, id), existingBalance + newDeposit);

        // Verify the registration on the compact
        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
    }

    /// @notice Test permit2Allocation with additionalCommitmentAmounts and witness in claimHash
    function test_permit2Allocation_withAdditionalCommitments_withWitness() public {
        uint256 existingBalance = defaultAmount;
        uint256 newDeposit = defaultAmount;
        uint256 additionalCommitment = existingBalance / 2;
        uint256 totalCommitment = newDeposit + additionalCommitment;

        // First, deposit tokens directly to the user (existing balance)
        usdc.mint(user, existingBalance);
        vm.startPrank(user);
        usdc.approve(address(compact), existingBalance);
        bytes12 lockTag = _getLockTag();
        uint256 id = compact.depositERC20(address(usdc), lockTag, existingBalance, user);
        vm.stopPrank();

        // Now do a permit2 allocation with additional commitment from existing balance
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);

        // Mint additional tokens for permit2 deposit
        usdc.mint(user, newDeposit);

        // Prepare token permissions for permit2
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), newDeposit);

        // Prepare deposit details
        DepositDetails memory details = _createDepositDetails(nonce, defaultExpiration, lockTag);

        // Create witness
        uint256 witnessValue = 12_345;
        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, witnessValue));

        // Compute claimHash with total commitment amount AND witness
        bytes32[] memory commitmentHashes = new bytes32[](1);
        commitmentHashes[0] = _computeCommitmentHash(id, totalCommitment);

        bytes32 claimHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH_WITH_WITNESS,
                arbiter,
                user,
                nonce,
                defaultExpiration,
                keccak256(abi.encodePacked(commitmentHashes)),
                witness
            )
        );

        // Create Permit2 signature with witness
        bytes memory permit2Signature =
            _createPermit2SignatureWithWitness(permitted, details, claimHash, userPrivateKey);

        // Create additional commitment amounts array
        uint256[] memory additionalCommitmentAmounts = new uint256[](1);
        additionalCommitmentAmounts[0] = additionalCommitment;

        // Create the commitments array for context signature
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: totalCommitment});

        // Create allocator signature for the additional commitments (context)
        bytes memory contextSignature =
            _createContextSignature(claimHash, commitments, additionalCommitmentAmounts, signerPrivateKey, true);

        // Execute permit2Allocation with the context signature and witness
        allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            additionalCommitmentAmounts,
            details,
            claimHash,
            WITNESS_STRING,
            witness,
            permit2Signature,
            contextSignature
        );

        // Verify claim is authorized
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));

        // Verify user has total balance (existing + new deposit)
        assertEq(compact.balanceOf(user, id), existingBalance + newDeposit);
    }

    /// @notice Test permit2Allocation reverts when additionalCommitmentAmounts exceed existing balance
    function test_permit2Allocation_revert_insufficientBalanceForAdditionalCommitments() public {
        uint256 existingBalance = defaultAmount;
        uint256 newDeposit = defaultAmount;
        uint256 additionalCommitment = existingBalance + 1; // Exceed existing balance

        // First, deposit tokens directly to the user (existing balance)
        usdc.mint(user, existingBalance);
        vm.startPrank(user);
        usdc.approve(address(compact), existingBalance);
        bytes12 lockTag = _getLockTag();
        compact.depositERC20(address(usdc), lockTag, existingBalance, user);
        vm.stopPrank();

        // Now try permit2 allocation with additionalCommitment > existing balance
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);

        // Mint additional tokens for permit2 deposit
        usdc.mint(user, newDeposit);

        // Prepare token permissions for permit2
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), newDeposit);

        // Prepare deposit details
        DepositDetails memory details = _createDepositDetails(nonce, defaultExpiration, lockTag);

        // Compute claimHash (doesn't matter, will revert before)
        uint256 id = AllocatorLib.toId(lockTag, address(usdc));
        bytes32[] memory commitmentHashes = new bytes32[](1);
        commitmentHashes[0] = _computeCommitmentHash(id, newDeposit + additionalCommitment);

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
        bytes memory permit2Signature = _createPermit2Signature(permitted, details, claimHash, userPrivateKey);

        // Create additional commitment amounts array
        uint256[] memory additionalCommitmentAmounts = new uint256[](1);
        additionalCommitmentAmounts[0] = additionalCommitment;

        // Create context signature (will not be validated since we'll revert before)
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: newDeposit + additionalCommitment});
        bytes memory contextSignature =
            _createContextSignature(claimHash, commitments, additionalCommitmentAmounts, signerPrivateKey, true);

        // Execute permit2Allocation should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                AllocatorLib.InvalidBalanceForAdditionalCommitments.selector,
                existingBalance, // available balance
                additionalCommitment // requested additional commitment
            )
        );
        allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            additionalCommitmentAmounts,
            details,
            claimHash,
            '',
            bytes32(0),
            permit2Signature,
            contextSignature
        );
    }

    /// @notice Test permit2Allocation reverts with invalid context signature for additionalCommitmentAmounts
    function test_permit2Allocation_revert_invalidContextSignature() public {
        uint256 existingBalance = defaultAmount;
        uint256 newDeposit = defaultAmount;
        uint256 additionalCommitment = existingBalance / 2;
        uint256 totalCommitment = newDeposit + additionalCommitment;

        // First, deposit tokens directly to the user (existing balance)
        usdc.mint(user, existingBalance);
        vm.startPrank(user);
        usdc.approve(address(compact), existingBalance);
        bytes12 lockTag = _getLockTag();
        uint256 id = compact.depositERC20(address(usdc), lockTag, existingBalance, user);
        vm.stopPrank();

        // Now do a permit2 allocation with additional commitment from existing balance
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);

        // Mint additional tokens for permit2 deposit
        usdc.mint(user, newDeposit);

        // Prepare token permissions for permit2
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), newDeposit);

        // Prepare deposit details
        DepositDetails memory details = _createDepositDetails(nonce, defaultExpiration, lockTag);

        // Compute claimHash with total commitment amount
        bytes32[] memory commitmentHashes = new bytes32[](1);
        commitmentHashes[0] = _computeCommitmentHash(id, totalCommitment);

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
        bytes memory permit2Signature = _createPermit2Signature(permitted, details, claimHash, userPrivateKey);

        // Create additional commitment amounts array
        uint256[] memory additionalCommitmentAmounts = new uint256[](1);
        additionalCommitmentAmounts[0] = additionalCommitment;

        // Create commitments for context signature
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: totalCommitment});

        // Create INVALID context signature - signed with wrong key (user instead of signer)
        bytes memory invalidContextSignature =
            _createContextSignature(claimHash, commitments, additionalCommitmentAmounts, userPrivateKey, true);

        // Execute permit2Allocation should revert with InvalidSignature
        vm.expectRevert(IHybridAllocator.InvalidSignature.selector);
        allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            additionalCommitmentAmounts,
            details,
            claimHash,
            '',
            bytes32(0),
            permit2Signature,
            invalidContextSignature
        );
    }

    /// @notice Test additionalCommitmentAmounts array length must match permitted length
    function test_permit2Allocation_revert_invalidAdditionalCommitmentsLength() public {
        bytes12 lockTag = _getLockTag();
        uint88 freeNonce = 1;
        uint256 nonce = _createPermit2Nonce(user, freeNonce);

        // Prepare token permissions
        ISignatureTransfer.TokenPermissions[] memory permitted = _createTokenPermissions(address(usdc), defaultAmount);

        // Prepare deposit details
        DepositDetails memory details = _createDepositDetails(nonce, defaultExpiration, lockTag);

        // Create dummy claimHash and signature
        bytes32 claimHash = bytes32(uint256(1));
        bytes memory signature = new bytes(64);

        // Create additionalCommitmentAmounts with wrong length
        uint256[] memory additionalCommitmentAmounts = new uint256[](2); // Should be 1

        vm.expectRevert(abi.encodeWithSelector(AllocatorLib.InvalidAdditionalCommitmentsLength.selector, 2, 1));
        allocator.permit2Allocation(
            arbiter,
            user,
            defaultExpiration,
            permitted,
            additionalCommitmentAmounts,
            details,
            claimHash,
            '',
            bytes32(0),
            signature,
            ''
        );
    }

    /// @notice Test prepareAllocation and executeAllocation flow with additionalCommitmentAmounts using off-chain nonce
    /// forge-config: default.isolate = false
    function test_prepareAndExecuteAllocation_withAdditionalCommitments() public {
        address recipient = makeAddr('recipient');
        uint256 existingBalance = defaultAmount;
        uint256 newDeposit = defaultAmount;
        uint256 additionalCommitment = existingBalance / 2;
        uint256 totalCommitment = newDeposit + additionalCommitment;

        // First, deposit tokens directly to the recipient (existing balance)
        usdc.mint(user, existingBalance);
        vm.startPrank(user);
        usdc.approve(address(compact), existingBalance);
        bytes12 lockTag = _getLockTag();
        uint256 id = compact.depositERC20(address(usdc), lockTag, existingBalance, recipient);
        vm.stopPrank();

        // Verify existing balance
        assertEq(compact.balanceOf(recipient, id), existingBalance);

        // Create off-chain nonce for the recipient
        uint88 freeNonce = 1;
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, recipient, freeNonce);

        // Create idsAndAmounts for the new deposit
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = id;
        idsAndAmounts[0][1] = newDeposit;

        // Create additional commitment amounts array
        uint256[] memory additionalCommitmentAmounts = new uint256[](1);
        additionalCommitmentAmounts[0] = additionalCommitment;

        // Compute claim hash with total commitment
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: totalCommitment});
        bytes32 claimHash = _toBatchCompactHash(
            BatchCompact({
                arbiter: arbiter,
                sponsor: recipient,
                nonce: nonce,
                expires: defaultExpiration,
                commitments: commitments
            })
        );

        // Create signer's signature for the HybridAllocationContext
        bytes memory contextSignature =
            _createContextSignature(claimHash, commitments, additionalCommitmentAmounts, signerPrivateKey, true);

        // Encode the HybridAllocationContext
        bytes memory context = _encodeHybridAllocationContext(nonce, contextSignature);

        // Fund and approve for the deposit
        usdc.mint(address(this), newDeposit);
        usdc.approve(address(compact), newDeposit);

        // Prepare allocation with context (off-chain nonce)
        uint256 returnedNonce = allocator.prepareAllocation(
            recipient,
            idsAndAmounts,
            additionalCommitmentAmounts,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0),
            context
        );
        assertEq(returnedNonce, nonce);

        // Deposit via Compact
        ITheCompact(compact).batchDeposit(idsAndAmounts, recipient);

        // Register the claim
        vm.prank(recipient);
        ITheCompact(compact).register(claimHash, BATCH_COMPACT_TYPEHASH);

        // Execute allocation with context
        allocator.executeAllocation(
            recipient,
            idsAndAmounts,
            additionalCommitmentAmounts,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0),
            context
        );

        // Verify claim is authorized
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));

        // Verify recipient has total balance (existing + new deposit)
        assertEq(compact.balanceOf(recipient, id), existingBalance + newDeposit);

        // Verify nonces counter was NOT incremented (off-chain nonces don't affect on-chain counter)
        assertEq(allocator.nonces(), 0);
    }

    /// @notice Test that executeAllocation reverts with additionalCommitmentAmounts when no context/signature is provided
    /// forge-config: default.isolate = false
    function test_executeAllocation_revert_additionalCommitmentsWithoutContext() public {
        address recipient = makeAddr('recipient');
        uint256 additionalCommitment = defaultAmount / 2;
        uint256 totalCommitment = defaultAmount + additionalCommitment;

        // First, deposit tokens directly to the recipient (existing balance)
        usdc.mint(user, defaultAmount);
        vm.startPrank(user);
        usdc.approve(address(compact), defaultAmount);
        bytes12 lockTag = _getLockTag();
        uint256 id = compact.depositERC20(address(usdc), lockTag, defaultAmount, recipient);
        vm.stopPrank();

        // Verify existing balance
        assertEq(compact.balanceOf(recipient, id), defaultAmount);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = id;
        idsAndAmounts[0][1] = defaultAmount;

        // Create non-zero additionalCommitmentAmounts
        uint256[] memory additionalCommitmentAmounts = new uint256[](1);
        additionalCommitmentAmounts[0] = additionalCommitment;

        // Fund and approve for the new deposit
        usdc.mint(address(this), defaultAmount);
        usdc.approve(address(compact), defaultAmount);

        // prepareAllocation without context succeeds (on-chain nonce is used)
        // Note: prepareAllocation uses (nonces + 1) but doesn't increment, executeAllocation uses ++nonces
        allocator.prepareAllocation(
            recipient,
            idsAndAmounts,
            additionalCommitmentAmounts,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0),
            ''
        );

        // Deposit via Compact
        ITheCompact(compact).batchDeposit(idsAndAmounts, recipient);

        // Compute the on-chain nonce that executeAllocation will use (++nonces, so 1 since nonces starts at 0)
        uint256 expectedNonce = _composeNonceUint(ON_CHAIN_NONCE, address(0), 1);

        // Compute the claim hash with the total commitment (including additionalCommitmentAmounts)
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: totalCommitment});
        bytes32 claimHash = _toBatchCompactHash(
            BatchCompact({
                arbiter: arbiter,
                sponsor: recipient,
                nonce: expectedNonce,
                expires: defaultExpiration,
                commitments: commitments
            })
        );

        // Register the claim so we can reach the InvalidSignature check
        vm.prank(recipient);
        ITheCompact(compact).register(claimHash, BATCH_COMPACT_TYPEHASH);

        // executeAllocation without context should revert because additionalCommitmentAmounts requires a signature
        vm.expectRevert(IHybridAllocator.InvalidSignature.selector);
        allocator.executeAllocation(
            recipient,
            idsAndAmounts,
            additionalCommitmentAmounts,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0),
            ''
        );
    }

    /// @notice Test prepareAllocation and executeAllocation flow with 65-byte signature
    /// forge-config: default.isolate = false
    function test_prepareAndExecuteAllocation_withAdditionalCommitments_65byteSignature() public {
        address recipient = makeAddr('recipient');
        uint256 existingBalance = defaultAmount;
        uint256 newDeposit = defaultAmount;
        uint256 additionalCommitment = existingBalance / 2;
        uint256 totalCommitment = newDeposit + additionalCommitment;

        // First, deposit tokens directly to the recipient (existing balance)
        usdc.mint(user, existingBalance);
        vm.startPrank(user);
        usdc.approve(address(compact), existingBalance);
        bytes12 lockTag = _getLockTag();
        uint256 id = compact.depositERC20(address(usdc), lockTag, existingBalance, recipient);
        vm.stopPrank();

        // Create off-chain nonce for the recipient
        uint88 freeNonce = 1;
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, recipient, freeNonce);

        // Create idsAndAmounts for the new deposit
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = id;
        idsAndAmounts[0][1] = newDeposit;

        // Create additional commitment amounts array
        uint256[] memory additionalCommitmentAmounts = new uint256[](1);
        additionalCommitmentAmounts[0] = additionalCommitment;

        // Compute claim hash with total commitment
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: totalCommitment});
        bytes32 claimHash = _toBatchCompactHash(
            BatchCompact({
                arbiter: arbiter,
                sponsor: recipient,
                nonce: nonce,
                expires: defaultExpiration,
                commitments: commitments
            })
        );

        // Create 65-byte signer's signature for the HybridAllocationContext
        bytes memory contextSignature65 =
            _createContextSignature(claimHash, commitments, additionalCommitmentAmounts, signerPrivateKey, false);

        // Encode the HybridAllocationContext with 65-byte signature
        bytes memory context = _encodeHybridAllocationContext(nonce, contextSignature65);

        // Fund and approve for the deposit
        usdc.mint(address(this), newDeposit);
        usdc.approve(address(compact), newDeposit);

        // Prepare allocation with context
        allocator.prepareAllocation(
            recipient,
            idsAndAmounts,
            additionalCommitmentAmounts,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0),
            context
        );

        // Deposit via Compact
        ITheCompact(compact).batchDeposit(idsAndAmounts, recipient);

        // Register the claim
        vm.prank(recipient);
        ITheCompact(compact).register(claimHash, BATCH_COMPACT_TYPEHASH);

        // Execute allocation with context (65-byte signature)
        allocator.executeAllocation(
            recipient,
            idsAndAmounts,
            additionalCommitmentAmounts,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0),
            context
        );

        // Verify claim is authorized
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));

        // Verify recipient has total balance
        assertEq(compact.balanceOf(recipient, id), existingBalance + newDeposit);
    }

    // ==================== Attestation Tests ====================

    /// @dev Helper to create an attestation signature
    function _createAttestationSignature(
        address sponsor,
        uint256 nonce,
        uint256 expires,
        Lock[] memory commitments,
        uint256 signerPk
    ) internal view returns (bytes memory) {
        // Create commitment hashes
        bytes32[] memory commitmentHashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; i++) {
            commitmentHashes[i] = keccak256(
                abi.encode(LOCK_TYPEHASH, commitments[i].lockTag, commitments[i].token, commitments[i].amount)
            );
        }
        bytes32 commitmentsHash = keccak256(abi.encodePacked(commitmentHashes));

        // Create hybrid attestation hash
        bytes32 hybridAttestationHash =
            keccak256(abi.encode(BATCH_COMPACT_TYPEHASH, address(compact), sponsor, nonce, expires, commitmentsHash));

        // Create digest with domain separator
        bytes32 domainSeparator = compact.DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), domainSeparator, hybridAttestationHash));

        // Sign with compact signature
        (bytes32 r, bytes32 vs) = vm.signCompact(signerPk, digest);
        return abi.encodePacked(r, vs);
    }

    /// @notice Test successful authorizeAttestation
    function test_authorizeAttestation_success() public {
        bytes12 lockTag = _getLockTag();

        // Create attestation parameters
        uint88 freeNonce = 1;
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce);
        uint256 expires = block.timestamp + 1 hours;

        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: defaultAmount});

        // Create signature
        bytes memory signature = _createAttestationSignature(user, nonce, expires, commitments, signerPrivateKey);

        // Authorize attestation
        bool authorized = allocator.authorizeAttestation(user, nonce, expires, commitments, signature);
        assertTrue(authorized);
    }

    /// @notice Test authorizeAttestation reverts when expired
    function test_authorizeAttestation_revert_AttestationExpired() public {
        bytes12 lockTag = _getLockTag();

        // Create attestation parameters with expired timestamp
        uint88 freeNonce = 1;
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce);
        uint256 expires = block.timestamp; // Already expired (expires <= block.timestamp)

        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: defaultAmount});

        bytes memory signature = _createAttestationSignature(user, nonce, expires, commitments, signerPrivateKey);

        vm.expectRevert(IHybridAllocator.AttestationExpired.selector);
        allocator.authorizeAttestation(user, nonce, expires, commitments, signature);
    }

    /// @notice Test authorizeAttestation reverts with invalid signature
    function test_authorizeAttestation_revert_InvalidSignature() public {
        bytes12 lockTag = _getLockTag();

        uint88 freeNonce = 1;
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce);
        uint256 expires = block.timestamp + 1 hours;

        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: defaultAmount});

        // Create signature with wrong key (userPrivateKey instead of signerPrivateKey)
        bytes memory wrongSignature = _createAttestationSignature(user, nonce, expires, commitments, userPrivateKey);

        vm.expectRevert(IHybridAllocator.InvalidSignature.selector);
        allocator.authorizeAttestation(user, nonce, expires, commitments, wrongSignature);
    }

    /// @notice Test authorizeAttestation reverts with invalid nonce command
    function test_authorizeAttestation_revert_InvalidNonceCommand() public {
        bytes12 lockTag = _getLockTag();

        // Use ON_CHAIN_NONCE instead of OFF_CHAIN_NONCE
        uint88 freeNonce = 1;
        uint256 nonce = _composeNonceUint(ON_CHAIN_NONCE, address(0), freeNonce);
        uint256 expires = block.timestamp + 1 hours;

        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: defaultAmount});

        bytes memory signature = _createAttestationSignature(user, nonce, expires, commitments, signerPrivateKey);

        vm.expectRevert(); // Will revert in verifyNonce
        allocator.authorizeAttestation(user, nonce, expires, commitments, signature);
    }

    /// @notice Test authorizeAttestation reverts when nonce already consumed
    function test_authorizeAttestation_revert_NonceAlreadyConsumed() public {
        bytes12 lockTag = _getLockTag();

        uint88 freeNonce = 1;
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce);
        uint256 expires = block.timestamp + 1 hours;

        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: defaultAmount});

        bytes memory signature = _createAttestationSignature(user, nonce, expires, commitments, signerPrivateKey);

        // First authorization succeeds
        allocator.authorizeAttestation(user, nonce, expires, commitments, signature);

        // Second authorization with same nonce should fail
        vm.expectRevert(); // Nonce already consumed by TheCompact
        allocator.authorizeAttestation(user, nonce, expires, commitments, signature);
    }

    /// @notice Test full attestation flow: authorizeAttestation then transfer
    /// forge-config: default.isolate = false
    function test_transfer_success_withAttestation() public {
        bytes12 lockTag = _getLockTag();
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        address target = makeAddr('target');

        // Deposit tokens to user
        vm.startPrank(user);
        usdc.approve(address(compact), defaultAmount);
        compact.depositERC20(address(usdc), lockTag, defaultAmount, user);
        vm.stopPrank();

        // Verify user has balance
        assertEq(compact.balanceOf(user, id), defaultAmount);

        // Create attestation parameters
        uint88 freeNonce = 1;
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce);
        uint256 expires = block.timestamp + 1 hours;

        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: defaultAmount});

        // Create signature and authorize attestation
        bytes memory signature = _createAttestationSignature(user, nonce, expires, commitments, signerPrivateKey);
        allocator.authorizeAttestation(user, nonce, expires, commitments, signature);

        // Now transfer should succeed
        vm.prank(user);
        compact.transfer(target, id, defaultAmount);

        // Verify transfer succeeded
        assertEq(compact.balanceOf(user, id), 0);
        assertEq(compact.balanceOf(target, id), defaultAmount);
    }

    /// @notice Test partial attestation: authorize more than transferred
    /// forge-config: default.isolate = false
    function test_transfer_success_partialAttestation() public {
        bytes12 lockTag = _getLockTag();
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        address target = makeAddr('target');

        // Deposit tokens to user
        vm.startPrank(user);
        usdc.approve(address(compact), defaultAmount);
        compact.depositERC20(address(usdc), lockTag, defaultAmount, user);
        vm.stopPrank();

        // Authorize full amount
        uint88 freeNonce = 1;
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce);
        uint256 expires = block.timestamp + 1 hours;

        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: defaultAmount});

        bytes memory signature = _createAttestationSignature(user, nonce, expires, commitments, signerPrivateKey);
        allocator.authorizeAttestation(user, nonce, expires, commitments, signature);

        // Transfer only half
        uint256 halfAmount = defaultAmount / 2;
        vm.prank(user);
        compact.transfer(target, id, halfAmount);

        // Verify partial transfer
        assertEq(compact.balanceOf(user, id), defaultAmount - halfAmount);
        assertEq(compact.balanceOf(target, id), halfAmount);

        // Transfer remaining should also work (within same transaction for transient storage)
        vm.prank(user);
        compact.transfer(target, id, halfAmount);

        assertEq(compact.balanceOf(user, id), 0);
        assertEq(compact.balanceOf(target, id), defaultAmount);
    }

    /// @notice Test attestation with multiple commitments
    /// forge-config: default.isolate = false
    function test_authorizeAttestation_multipleCommitments() public {
        // Both tokens use the same lockTag (same allocator, scope, resetPeriod)
        bytes12 lockTag = _getLockTag();
        uint256 usdcId = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        uint256 daiId = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(dai));
        address target = makeAddr('target');

        // Deposit both tokens (using the same lockTag for both)
        vm.startPrank(user);
        usdc.approve(address(compact), defaultAmount);
        dai.approve(address(compact), defaultAmount);
        compact.depositERC20(address(usdc), lockTag, defaultAmount, user);
        compact.depositERC20(address(dai), lockTag, defaultAmount, user);
        vm.stopPrank();

        // Create attestation for both tokens
        uint88 freeNonce = 1;
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce);
        uint256 expires = block.timestamp + 1 hours;

        Lock[] memory commitments = new Lock[](2);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: defaultAmount});
        commitments[1] = Lock({lockTag: lockTag, token: address(dai), amount: defaultAmount});

        bytes memory signature = _createAttestationSignature(user, nonce, expires, commitments, signerPrivateKey);
        allocator.authorizeAttestation(user, nonce, expires, commitments, signature);

        // Transfer both tokens
        vm.startPrank(user);
        compact.transfer(target, usdcId, defaultAmount);
        compact.transfer(target, daiId, defaultAmount);
        vm.stopPrank();

        // Verify both transfers
        assertEq(compact.balanceOf(user, usdcId), 0);
        assertEq(compact.balanceOf(user, daiId), 0);
        assertEq(compact.balanceOf(target, usdcId), defaultAmount);
        assertEq(compact.balanceOf(target, daiId), defaultAmount);
    }

    /// @notice Test that multiple attestations for the same token accumulate (additive behavior)
    /// forge-config: default.isolate = false
    function test_authorizeAttestation_additiveAmounts() public {
        bytes12 lockTag = _getLockTag();
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        address target = makeAddr('target');

        // Deposit tokens to user
        vm.startPrank(user);
        usdc.approve(address(compact), defaultAmount);
        compact.depositERC20(address(usdc), lockTag, defaultAmount, user);
        vm.stopPrank();

        uint256 halfAmount = defaultAmount / 2;
        uint256 expires = block.timestamp + 1 hours;

        // First attestation: authorize half amount
        uint88 freeNonce1 = 1;
        uint256 nonce1 = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce1);
        Lock[] memory commitments1 = new Lock[](1);
        commitments1[0] = Lock({lockTag: lockTag, token: address(usdc), amount: halfAmount});
        bytes memory signature1 = _createAttestationSignature(user, nonce1, expires, commitments1, signerPrivateKey);
        allocator.authorizeAttestation(user, nonce1, expires, commitments1, signature1);

        // Second attestation: authorize another half amount (different nonce)
        uint88 freeNonce2 = 2;
        uint256 nonce2 = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce2);
        Lock[] memory commitments2 = new Lock[](1);
        commitments2[0] = Lock({lockTag: lockTag, token: address(usdc), amount: halfAmount});
        bytes memory signature2 = _createAttestationSignature(user, nonce2, expires, commitments2, signerPrivateKey);
        allocator.authorizeAttestation(user, nonce2, expires, commitments2, signature2);

        // Transfer full amount should succeed (half + half = full)
        vm.prank(user);
        compact.transfer(target, id, defaultAmount);

        // Verify transfer succeeded
        assertEq(compact.balanceOf(user, id), 0);
        assertEq(compact.balanceOf(target, id), defaultAmount);
    }

    /// @notice Test that transfer fails when attestation amount is insufficient
    /// forge-config: default.isolate = false
    function test_transfer_revert_InsufficientAttestationAmount() public {
        bytes12 lockTag = _getLockTag();
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        address target = makeAddr('target');

        // Deposit tokens to user
        vm.startPrank(user);
        usdc.approve(address(compact), defaultAmount);
        compact.depositERC20(address(usdc), lockTag, defaultAmount, user);
        vm.stopPrank();

        // Authorize only half amount
        uint256 reducedAmount = defaultAmount - 1;
        uint88 freeNonce = 1;
        uint256 nonce = _composeNonceUint(OFF_CHAIN_NONCE, user, freeNonce);
        uint256 expires = block.timestamp + 1 hours;

        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: reducedAmount});

        bytes memory signature = _createAttestationSignature(user, nonce, expires, commitments, signerPrivateKey);
        allocator.authorizeAttestation(user, nonce, expires, commitments, signature);

        // Try to transfer full amount should fail
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IHybridAllocator.InsufficientAttestationAmount.selector, reducedAmount, defaultAmount
            ),
            address(allocator)
        );
        compact.transfer(target, id, defaultAmount);
    }
}
