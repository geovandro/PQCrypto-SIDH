/********************************************************************************************
* Faster isogeny-based compressed key agreement
*
*
* Abstract: entangled basis generation parameters and tables
*
* Author: Geovandro C. C. F. Pereira
*********************************************************************************************/  

#include "SIDH_internal.h"


// This file contains:
// Constants u and u0 where u = u0^2 in F_{p^2} \ F_p used in entagled basis generation
// For the 2^eA-torsion basis generation:
//      Two tables of 17 elements each for the values r in F_p such that v = 1/(1+ur^2) where r is already converted to Montgomery representation
//      Also, 2 tables for the quadratic residues (qr) and quadratric non residues (qnr) v in F_{p^2} with 17 GF(p^2) elements each. 
// For the 3^eB-torsion basis generation:
//      A table of size 20 for values v = 1/(1+U*r^2) where U = 4+i


const uint64_t u_entang[2*NWORDS64_FIELD] = {
                                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 
                                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 
                                0x000000000004935a, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0620000000000000, 
                                0xaa4f63c86eb8d8cd, 0xd2ef2f7e7e9e49a0, 0x913b6f6558b89c5c, 0x99496873a40ed2ad, 0x21ef24d8ea258fd2, 0x00005ab64979cbc4};

const uint64_t u0_entang[2*NWORDS_FIELD] = {
                                0x00000000000249ad, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8310000000000000,
                                0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x00002d5b24bce5e2,
                                0x00000000000249ad, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8310000000000000,
                                0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x00002d5b24bce5e2};

// Tables for quadratic residues and quadratic non residues v with 17 elements each. 

const uint64_t table_r_qr[17][NWORDS_FIELD] = { 
{0x00000000000249ad, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8310000000000000, 0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x2d5b24bce5e2},
{0x00000000000926b5, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x1d90000000000000, 0x70b2310b937938f1, 0xcb48c3e2e944c6ca, 0x1a284662da855042, 0xad301be2eb6b4e13, 0x35cbb9123c90433e, 0x4586bdb1a06c},
{0x00000000000dba10, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x3500000000000000, 0x3714fe4eb8399915, 0xc3a2584753eb43f4, 0xa3151d605c520428, 0xc116cf5232c7c978, 0x49a84d4b8efaf6aa, 0x305731e97514},
{0x00000000001003bd, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xb810000000000000, 0x8c3cb032ef96057b, 0x2d19f006933a68c4, 0x6bb2d51308ae5257, 0x0dbb838c04cf32cf, 0x5a9fdfb8040dbe94, 0x5db256a65af6},
{0x0000000000124d6b, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x4c70000000000000, 0xfd77cb91dcf9f939, 0xbbfbecabbe91c11d, 0x2c01f45dde1eb80e, 0xd4fd82c17a2444de, 0x5d84e184e165aa16, 0x1b27a62149bc},
{0x0000000000149718, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xcf80000000000000, 0x529f7d761456659f, 0x2573846afde0e5ee, 0xf49fac108a7b063d, 0x21a236fb4c2bae34, 0x6e7c73f156787200, 0x4882cade2f9e},
{0x0000000000192a73, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xe6f0000000000000, 0x19024ab93916c5c3, 0x1dcd18cf68876318, 0x7d8c830e0c47ba23, 0x3588ea6a9388299a, 0x8259082aa8e3256c, 0x33533f160446},
{0x00000000001dbdce, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xfe60000000000000, 0xdf6517fc5dd725e7, 0x1626ad33d32de041, 0x06795a0b8e146e09, 0x496f9dd9dae4a500, 0x96359c63fb4dd8d8, 0x1e23b34dd8ee},
{0x0000000000249ad6, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x98e0000000000000, 0xfaef9723b9f3f272, 0x77f7d9577d23823b, 0x5803e8bbbc3d701d, 0xa9fb0582f44889bc, 0xbb09c309c2cb542d, 0x364f4c429378},
{0x0000000000292e31, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xb050000000000000, 0xc1526466deb45296, 0x70516dbbe7c9ff65, 0xe0f0bfb93e0a2403, 0xbde1b8f23ba50521, 0xcee6574315360799, 0x211fc07a6820},
{0x00000000002b77de, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x3360000000000000, 0x167a164b1610befd, 0xd9c9057b27192436, 0xa98e776bea667231, 0x0a866d2c0dac6e78, 0xdfdde9af8a48cf83, 0x4e7ae5374e02},
{0x00000000002dc18c, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xc7c0000000000000, 0x87b531aa0374b2ba, 0x68ab022052707c8f, 0x69dd96b6bfd6d7e9, 0xd1c86c6183018087, 0xe2c2eb7c67a0bb05, 0xbf034b23cc8},
{0x0000000000300b39, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x4ad0000000000000, 0xdcdce38e3ad11f21, 0xd22299df91bfa15f, 0x327b4e696c332617, 0x1e6d209b5508e9de, 0xf3ba7de8dcb382ef, 0x394b596f22aa},
{0x00000000003254e6, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xcde0000000000000, 0x32049572722d8b87, 0x3b9a319ed10ec630, 0xfb19061c188f7446, 0x6b11d4d527105334, 0x04b2105551c64ad8, 0x66a67e2c088d},
{0x0000000000349e94, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x6240000000000000, 0xa33fb0d15f917f45, 0xca7c2e43fc661e89, 0xbb682566edffd9fd, 0x3253d40a9c656543, 0x079712222f1e365b, 0x241bcda6f753},
{0x00000000003b7b9c, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xfcc0000000000000, 0xbeca2ff8bbae4bcf, 0x2c4d5a67a65bc083, 0x0cf2b4171c28dc12, 0x92df3bb3b5c94a00, 0x2c6b38c7f69bb1b0, 0x3c47669bb1dd},
{0x00000000003dc549, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x7fd0000000000000, 0x13f1e1dcf30ab836, 0x95c4f226e5aae554, 0xd5906bc9c8852a40, 0xdf83efed87d0b356, 0x3d62cb346bae7999, 0x69a28b5897bf},
};

const uint64_t table_r_qnr[17][NWORDS_FIELD] = {
{0x000000000004935a, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0620000000000000, 0xaa4f63c86eb8d8cd, 0xd2ef2f7e7e9e49a0, 0x913b6f6558b89c5c, 0x99496873a40ed2ad, 0x21ef24d8ea258fd2, 0x5ab64979cbc4},
{0x000000000006dd08, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x9a80000000000000, 0x1b8a7f275c1ccc8a, 0x61d12c23a9f5a1fa, 0x518a8eb02e290214, 0x608b67a91963e4bc, 0x24d426a5c77d7b55, 0x182b98f4ba8a},
{0x00000000000b7063, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xb1f0000000000000, 0xe1ed4c6a80dd2cae, 0x5a2ac088149c1f23, 0xda7765adaff5b5fa, 0x74721b1860c06021, 0x38b0badf19e82ec1, 0x2fc0d2c8f32},
{0x000000000016e0c6, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x63e0000000000000, 0xc3da98d501ba595d, 0xb455811029383e47, 0xb4eecb5b5feb6bf4, 0xe8e43630c180c043, 0x716175be33d05d82, 0x5f81a591e64},
{0x00000000001b7420, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x6a00000000000000, 0x6e29fc9d7073322a, 0x8744b08ea7d687e8, 0x462a3ac0b8a40851, 0x822d9ea4658f92f1, 0x93509a971df5ed55, 0x60ae63d2ea28},
{0x000000000020077b, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8170000000000000, 0x348cc9e09533924e, 0x7f9e44f3127d0512, 0xcf1711be3a70bc37, 0x96145213acec0e56, 0xa72d2ed07060a0c1, 0x4b7ed80abed0},
{0x0000000000225129, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x15d0000000000000, 0xa5c7e53f8297860c, 0x0e8041983dd45d6b, 0x8f6631090fe121ef, 0x5d56514922412065, 0xaa12309d4db88c44, 0x8f42785ad96},
{0x000000000026e483, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x1bf0000000000000, 0x50174907f1505ed9, 0xe16f7116bc72a70c, 0x20a1a06e6899be4b, 0xf69fb9bcc64ff313, 0xcc01557637de1c16, 0x63aa70ff795a},
{0x000000000036e841, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xe550000000000000, 0xf86762b596edebab, 0x33f3c6033bb54359, 0x8405dd199a5c282c, 0x7ef888446e6cce9a, 0x188ea48ea430fe44, 0x5176f263dd35},
{0x00000000003931ef, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x79b0000000000000, 0x69a27e148451df69, 0xc2d5c2a8670c9bb3, 0x4454fc646fcc8de3, 0x463a8779e3c1e0a9, 0x1b73a65b8188e9c7, 0xeec41decbfb},
{0x0000000000400ef7, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x1430000000000000, 0x852cfd3be06eabf4, 0x24a6eecc11023dad, 0x95df8b149df58ff8, 0xa6c5ef22fd25c565, 0x4047cd014906651c, 0x2717dad38685},
{0x00000000004258a4, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x9740000000000000, 0xda54af2017cb185a, 0x8e1e868b5051627d, 0x5e7d42c74a51de26, 0xf36aa35ccf2d2ebc, 0x513f5f6dbe192d05, 0x5472ff906c67},
{0x000000000044a252, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x2ba0000000000000, 0x4b8fca7f052f0c18, 0x1d0083307ba8bad7, 0x1ecc62121fc243de, 0xbaaca292448240cb, 0x5424613a9b711888, 0x11e84f0b5b2d},
{0x000000000046ebff, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xaeb0000000000000, 0xa0b77c633c8b787e, 0x86781aefbaf7dfa7, 0xe76a19c4cc1e920c, 0x075156cc1689aa21, 0x651bf3a71083e072, 0x3f4373c8410f},
{0x00000000004935ac, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x31c0000000000000, 0xf5df2e4773e7e4e5, 0xefefb2aefa470477, 0xb007d177787ae03a, 0x53f60b05e8911378, 0x761386138596a85b, 0x6c9e988526f1},
{0x00000000004dc907, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x4930000000000000, 0xbc41fb8a98a84509, 0xe849471364ed81a1, 0x38f4a874fa479420, 0x67dcbe752fed8ede, 0x89f01a4cd8015bc7, 0x576f0cbcfb99},
{0x0000000000525c62, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x60a0000000000000, 0x82a4c8cdbd68a52d, 0xe0a2db77cf93fecb, 0xc1e17f727c144806, 0x7bc371e4774a0a43, 0x9dccae862a6c0f33, 0x423f80f4d041},
};


const uint64_t table_v_qr[34][NWORDS_FIELD] = {
{0xcccccccccccd41ef, 0xcccccccccccccccc, 0xcccccccccccccccc, 0xcccccccccccccccc, 0xcccccccccccccccc, 0x467ccccccccccccc, 
 0x05ccf962f575df8b, 0x3953c2ca47d95926, 0xc50bc81a120a6c9f, 0xde486c73b57c04c7, 0x3c38f0bbedb4e68a, 	 0x35d48fd9c405}, 
{0x6666666666657c21, 0x6666666666666666, 0x6666666666666666, 0x6666666666666666, 0x6666666666666666, 0x61b6666666666666, 
 0xd852a3bf5f0cb992, 0x67ee158584451a2a, 0x7e370833b2d70f38, 0xc8d1dc1cf1ba4db8, 0x95a0af27bc510f50, 	  0x43cb58e6f11},
{0xb891db891db8926d, 0xdb891db891db891d, 0x1db891db891db891, 0x91db891db891db89, 0x891db891db891db8, 0xb7a1db891db891db, 
 0x7667ea3e359a528f, 0x920f68111bc2395b, 0x73153df2ce971e2c, 0x16eda0d863ac7da5, 0xbf837289a3fc18bf, 	 0x5adf5c37ba11}, 
{0xedc48edc48edb246, 0x8edc48edc48edc48, 0x48edc48edc48edc4, 0xc48edc48edc48edc, 0xdc48edc48edc48ed, 0x49a48edc48edc48e, 
 0x590a01c2cff1ef31, 0xf144be828ee398a4, 0x7553bc320111d67f, 0xae524764f48d28a2, 0x7d745f00e9774a86, 	  0x16c21bbd6a1},
{0x5e40e05a0e84063c, 0x1f4d776f0a51a9cb, 0xcb5e40e05a0e8406, 0x061f4d776f0a51a9, 0xa9cb5e40e05a0e84, 0x72c61f4d776f0a51, 
 0x618b216fb9c76a1e, 0xe22409f266b16463, 0x894a7d245553fd6b, 0x4e89f364cce00fa7, 0x77a8c743f3083ec9, 	 0x188be18d4ac5}, 
{0x7dc0e6abeade3f10, 0x323668c519083ecd, 0xcd7dc0e6abeade47, 0x47323668c519083e, 0x3ecd7dc0e6abeade, 0xa347323668c51908, 
 0xcfa800e85f71b1fe, 0x0f36e5745d988b7a, 0xe7f654456f1f4116, 0x3f5edbec2c210d61, 0x39b0fedd215c1dca, 	 0x1705e4626a37},
{0x791c39ad37694088, 0x40791c39ad376940, 0x6940791c39ad3769, 0x376940791c39ad37, 0xad376940791c39ad, 0x6c2d376940791c39, 
 0x4a463885b9946d81, 0x736b37a93397fe42, 0x3874f55b29bb4d54, 0x5f7a8a5f8d7543c5, 0x228ccba8f76bd619, 	 0x5096624d7492},
{0xa331ebb0c9b54ba9, 0x51a331ebb0c9b551, 0xb551a331ebb0c9b5, 0xc9b551a331ebb0c9, 0xb0c9b551a331ebb0, 0xc980c9b551a331eb, 
 0xc7bc1bc679178b4e, 0x7072b575c98a5f98, 0xb10657e6a1b9dea2, 0x71773ba18e92437a, 0xad4025945d8b2ab8, 	 0x2f2c83a4e8d6},
{0x732233773223377c, 0x3773223377322337, 0x2337732233773223, 0x3223377322337732, 0x7732233773223377, 0xc637322337732233, 
 0x2695c5c06b69b3f6, 0x02330b3c47a0d9f3, 0x1ff319b45bec27c0, 0xa128906c609ee6b9, 0x736a7518122e449f, 	 0x1fce86244e63},
{0x6ee64466ee6441db, 0x466ee64466ee6446, 0x64466ee64466ee64, 0xee64466ee64466ee, 0x66ee64466ee64466, 0x63d6ee64466ee644, 
 0xa64ee10dfc0f7507, 0x7e19cca11263939b, 0x39cf2cd41a04b92c, 0xb2fbf371165340d9, 0x53745b07d6df8b00, 	 0x44f4c0618554},
{0x70e5437d550c15e9, 0x514ab52cdc183ac2, 0xa4d63dfa7aa6594a, 0x046dad39bc3f3f19, 0x82fd5b4a38522b72, 0xad58a5aa7e8d2ecf, 
 0x523baab70a135be2, 0x45782546050175f7, 0xb24f33faa2472b55, 0xeba7a14c1f8593cd, 0x20600fbab2d24e65, 	 0x133d309f7ec7},
{0x8eeb4ab02e5a2272, 0x8eb9599cb8aad0f4, 0xb06cc77e62bb7ef8, 0x32986176dffa11c5, 0x1bac3b085c0081d9, 0x69272a1beaa860af, 
 0xe41e6ebfb6ed0d08, 0xf255608b042db67e, 0x1279c6c0d0c40109, 0x76b7ba4e30fa03b6, 0x0d3ddd4f6f5a7eb7, 	 0x106a8e48cd0f},
{0xd5120148feaf2c06, 0x255365f9daa4c4b8, 0xcc272efc74777061, 0xd9e68887c98d5c50, 0x0383b3424e91729b, 0xe0b5120148feaf2c, 
 0x1be4fa2b9f7cfd78, 0xda98a1c587680dd9, 0xacc09e7217ddd41d, 0xbab5e239d699c58c, 0x41fd047089438309, 	  0x858395e2c66},
{0x94fac8ff3e686241, 0xb72999cf503e0946, 0x02f59559e717c42a, 0x0412efa3785ebb9f, 0xad808b51ba81a8ac, 0x4be4fac8ff3e6864, 
 0x8c1aaea7b9495845, 0x94d196357b071596, 0x4fbf87da63cfbc99, 0x666394a603dfbb5d, 0xaa328976810c7c69, 	 0x6aa898df5e6a},
{0x40e70907368faaa3, 0x2531ec3903ce9f2c, 0xf8ab9bfacf708d95, 0xd2de3a9b1838859a, 0x4e47b12d7c682948, 0x281bdc83c4953f02, 
 0xde0ef99abed7afea, 0xb81783a3e8034ae6, 0x3e73219aac32b265, 0xa6f25c569e80f4d3, 0x6961e44d2e61e550, 	 0x54af9d7748ce},
{0x4ef61479f650b3ca, 0xe4161cb8f931d792, 0xad6c0eda1d651114, 0x96969f3a055f9963, 0xa55811f1be797dd9, 0xbb36da0672f2cef4, 
 0xbcd0f6f9ffb265c5, 0x868f4baba3739212, 0xda96099f90f8ec8d, 0xf6b719ff6c14091f, 0xef5131b07d9ba208, 	 0x15f75a78fb86},
{0xb5ca528d6b5ca529, 0xca528d6b5ca528d6, 0x528d6b5ca528d6b5, 0x8d6b5ca528d6b5ca, 0x6b5ca528d6b5ca52, 0xb27528d6b5ca528d, 
 0xd7c00a95fc590145, 0x4e4610b31250410d, 0x92eb9c10c371f0fc, 0x71d124ad03784c6d, 0xfba87309e1a6d857, 	 0x2df3b0f268cd},
{0x6b5ae52946b5ad2d, 0x5ae52946b5ae5294, 0xe52946b5ae52946b, 0x2946b5ae52946b5a, 0x46b5ae52946b5ae5, 0xd0be52946b5ae529, 
 0x5beae3e345c8e7d7, 0x9d2d7059d4bb6a4e, 0x018f7c0f408ea159, 0x4e11d89176651539, 0x48671fc6c152f99c, 	 0x530ce08d1028},
{0xce57aa6b0a6e427f, 0x9b8f883433a0eb6a, 0xbd90869a824e3109, 0xd1840719519276ea, 0xf601cd0a72f12455, 0x8904c6a15653d646, 
 0x072db02908565884, 0x71294dc40dc2eb13, 0x361608701cea745e, 0x1279cc6c51a4f800, 0xdd923715582e9ede, 	 0x6578e5cc44c5},
{0xb218a10d98e7ac3c, 0x3caf3bdd50ac19a5, 0x2a2b48e62a13dfae, 0xa9ce07e98542fdd0, 0x4b70fd8d0d9c06c5, 0x6829379d7bc99c61, 
 0x57c3d248cc251489, 0x9f1367a307c698e9, 0x2cc0b2b8746361ef, 0x9a6a53d6400cb8ea, 0x7888c0894b30195b, 	 0x29e026757f97},
{0xb7b49e77dd01b05a, 0xc7fcde689ea7a30e, 0x3b83e48534d253e7, 0xe1f4f28b24c70d5f, 0x0c226af798cdae97, 0x29592ffaba44e0bf, 
 0x451bffacf7902a0b, 0xef0c4136db713262, 0x7f066b8d7cd90c93, 0x193c99bb6a2bd9e4, 0xdcceb7dd7547e7ee, 	 0x1bc6242c97db},
{0xe49911f2b13ca178, 0xf8d4bcf08b36207d, 0x2605805106cf5c4d, 0xbb2bf392469c496a, 0xc6ee51b30be997a4, 0x3636aedea9be252f, 
 0x5962bfe5ce1e434d, 0x80a1219f24fbaa71, 0x9727d3f901b9fa59, 0x9c7db47fbdb8d837, 0x260b21a1ea96da92, 	 0x58c7ec9d75a5},
{0x11372fcc7943203a, 0x5c4549b345de13e1, 0xb35e08aa984d8eeb, 0x9ad22a4f3d9cf45d, 0x84408fbe68108c13, 0xd6f34279ba1d5079, 
 0xfd86bce1d485ce9c, 0x7547dcc9e6a72b9a, 0x082bac6e5640d1b8, 0xa0aa9060525b5fa0, 0x9df6b6008023369a, 	 0x64534002fc0f},
{0x338aa1050e3b47f2, 0xa779afc5aa01e0aa, 0x7a24eae40da1607f, 0x2f3bc85f75845b2f, 0xb63eccfacc4a42bc, 0xb970439a64648442, 
 0xfc7fe81d54bcbfad, 0x8f070c333697311a, 0xc3f49a6f3f169cea, 0x05d4853a9ea5f7ed, 0xd518de0b200b8454, 	 0x527415af5fe1},
{0x29d6c703462657ad, 0xdc60db370d32f7b9, 0x7ecf292bc2c418dd, 0x37b10e0d29478fc0, 0x2dfafef9ea3b8e16, 0xe9716b45fa8908a4, 
 0x6cb32b342a6375ff, 0xfd73f31ab04928c5, 0xb397940272f73c0c, 0x5b001264620355c2, 0x5803f26169f9945b, 	 0x5c5620099d9b},
{0xda0656b84fe5eb1e, 0xba4cbc548666840d, 0x1a44273af862539e, 0x1ffd96a7c772bacb, 0x953d86f6fed07774, 0x7bbc68e6d3e03a59, 
 0xa78131504fea94b4, 0x5ff580356c9ef9e7, 0xdf4576db17102d3c, 0xca73668debaabc08, 0xc73232385d81a0cb, 	 0x14dc1275b692},
{0xe1c98f3c564a49cd, 0x76847854dfff1979, 0x6dd3a9a2b019d474, 0xfeb9a85944a3c836, 0x4c554e80a25debb9, 0xc247dbf7209cba59, 
 0xe606e4da4d403e68, 0x5aabae35231e6c78, 0x1e08f32d70b4cf5a, 0x8edd7b4a0d3949fa, 0xa549cbae571fabd6, 	 0x345b562bb1c2},
{0x3dda63d9b718ef13, 0xdb18ff110367ab22, 0xb7a690d61e54a79f, 0xd1fb6e7474b2f230, 0x5d6f299a0cdca8b4, 0xbdb8418caf5f5e57, 
 0x87950067c9c186cf, 0xf190bc388a72a53b, 0x213c2bed23c24ca9, 0xd23020b606f4b8b5, 0xe7cfbf2e0de63e1d, 	  0x85488821ca3},
{0x2e87222f0886018b, 0x2006a348352327dc, 0x019561fc0617f066, 0x0390fd49917ead64, 0xc8962e05be5c859e, 0x9098f7d823688e17, 
 0xa367361fe7730947, 0x4c6ae2f141441363, 0x6012b07c3ca41e86, 0xb27005c079feb1b6, 0x825b9bfc26c91f27, 	 0x3f1183f8513f},
{0xb584b99ec62d9d35, 0xa4912f9464b54407, 0x74a10c6ed11079ef, 0x42c935f4b27768b1, 0x0355cc43459fc8f5, 0x083fb4bda9e4c1b5, 
 0x362d54faf7050831, 0xed24cac0d587af78, 0x520c08b595def623, 0x9c385db3fd4b1742, 0x12b09c148b913905, 	 0x4c96ea957bf4},
{0xccb2ce7886ef239d, 0x47c704f6f492b661, 0x63cdc17f473b3143, 0xe43575f9dedacc50, 0xed36745a83436e23, 0xb43e3a2a47d36381, 
 0x6fe523a476bf9f48, 0x082b1f402b3bd2a0, 0xdbe6e728b539adae, 0xa37c34807a76ff4e, 0x538ee747772483fb, 	  0xdb5a5e658a6},
{0xefad9377610bea32, 0xecedc7c4592ccb7e, 0xe95a17cfcf63d4ac, 0xc5a8f05f0c78f770, 0x386981fac3e25272, 0xdd7cd0b4ab9a79d3, 
 0xd9455ddad31d0592, 0x994588049ebe35c8, 0x07820458445b7df6, 0x160c1a4d5730403c, 0xd554560f2a51e183, 	 0x27b420420dc7},
{0xed6f9f18f5f91d9b, 0xd0140983a4c9f4fa, 0x4b28e37741fcec6e, 0x58485d7e32af47f7, 0xbfcad3b8ef182455, 0xaa683462489724d5, 
 0x4f7f01fffd1c1e61, 0xdb4f6a13aebb1aca, 0x40272ae951d7ad1b, 0x430f04d3c2402c98, 0x67c05bfad21baaf1, 	 0x53d2c0cd2c47},
{0xba47e3d71b355ef5, 0xede1d03f79cac2e3, 0xf12082ca2d8570e2, 0x33db874355b82195, 0xaed62cbe488111ef, 0x8ff5a83e933036a1, 
 0x5fc5432547b62106, 0x3675123e1b5d6362, 0x187e4e847edf9acc, 0x92e55d9773f0ab6e, 0x2fb79ee22f3b6fa7, 	 0x59f9721ddc1b}
};

const uint64_t table_v_qnr[34][NWORDS_FIELD] = {
{0xe85e85e85e85f161, 0x5e85e85e85e85e85, 0x85e85e85e85e85e8, 0xe85e85e85e85e85e, 0x5e85e85e85e85e85, 0x65385e85e85e85e8, 
 0x85f916a5f6e08638, 0x2609c462575e3a01, 0xd55bc460bffdb5f7, 0x394fd56c08877041, 0x90a4c64e64b48269, 0x0000155b182e978e}, 
{0xbd0bd0bd0bd074f6, 0x0bd0bd0bd0bd0bd0, 0xd0bd0bd0bd0bd0bd, 0xbd0bd0bd0bd0bd0b, 0x0bd0bd0bd0bd0bd0, 0xb39d0bd0bd0bd0bd, 
 0x981077dadcecbf8e, 0x84dd13216cfdc8e1, 0x65bf0dc9adea2134, 0x4046bea875292c81, 0x96feeecc09d1a583, 0x000034f2e90f31c3},
{0x94dfb461ac813046, 0x794dfb461ac812e7, 0xe794dfb461ac812e, 0x2e794dfb461ac812, 0x12e794dfb461ac81, 0x3d0e794dfb461ac8, 
 0x70595ed790f5300a, 0x8ac21df01d745314, 0x960e4f84da8d1645, 0x5b7e64183952e46b, 0xf22c180908c76b1f, 0x00004768eb30e5c6}, 
{0x88455121deea9b08, 0x788455121deeabb7, 0xb788455121deeabb, 0xbb788455121deeab, 0xabb788455121deea, 0xe53b788455121dee, 
 0xc8ce631746684732, 0x7d5d2a56dd6fbe22, 0xd6ad8d86b52354ae, 0xd1bd7280508807cf, 0xa1c516d87ebccc99, 0x0000396575a76d53},
{0xd62298eca7759c89, 0x4d62298eca7759c4, 0xc4d62298eca7759c, 0x9c4d62298eca7759, 0x59c4d62298eca775, 0x796c4d62298eca77, 
 0xae6dbc543fef825c, 0xec1f7e95b33ed029, 0xca719faf0d52eaca, 0xf0376be32d0bf058, 0xf65ba4732a06cb30, 0x0000253e29fda895}, 
{0x2d3e21c74b076d2d, 0xe2d3e21c74b0778e, 0x8e2d3e21c74b0778, 0x78e2d3e21c74b077, 0x778e2d3e21c74b07, 0x2288e2d3e21c74b0, 
 0x114736656cb88d28, 0x65c8937e512febc1, 0x0306eeb4ab789442, 0xf0baf2eb5b82da71, 0xd1557c1ade14f33f, 0x0000281ef5d67b92},
{0x55a7cc22bd034bc5, 0xcf664d2b55543db8, 0xad0509637903bb29, 0xcc764b6db31cc125, 0xa38de755c3a64634, 0xc5dbc1418728812c, 
 0x54cdbea5daab0ebf, 0x784da3fdee94f653, 0xacd92fabb346e2c0, 0x309e575438f3301c, 0xde6da98747e3bc84, 0x00000078998a0688},
{0x14e884dc556cce17, 0xf813b625562fc7fd, 0xd410aa497515c755, 0x4395124c11891a90, 0x392344ff261926c0, 0x5b0104ce685b1520, 
 0xa32fa4f27454f2d6, 0xdded7cb7af975b5c, 0xfea15a43c78ac218, 0x89ae7b37deb4c0e0, 0x48661eef6dcf9520, 0x000011ade16cdc2e},
{0xd2261143e5b763c9, 0x7baf0692270e1a07, 0x3e5b763c797e0b76, 0x2270e1a07d226114, 0xc797e0b767baf069, 0x8fa2261143e5b763, 
 0x6f563606e110ed58, 0xcd1c300154910aa4, 0xb61edfd60c5c6096, 0x12cadf965191532e, 0xa045ca5ade8c8ca6, 0x00002cdc07a09f1d}, 
{0x952c939d91afbd6c, 0xdb189b941022b733, 0xd91afbf752331ab4, 0x41022b733952c939, 0x752331ab4db189b9, 0x91552c939d91afbf, 
 0x06376ca8518ba8ea, 0x4c144651e91cace2, 0xe0e13e3f7af8ac34, 0x4c7e7cde3d51f816, 0x11e5e216628da39f, 0x00003c9c0d30f762},
{0x0c605daac2686111, 0x653b01b6dab28c3b, 0xc50a3a32de5449a4, 0xb6ebc1c42e96427e, 0x8feffae8a88084d9, 0x58ea39884624c641, 
 0x9ec005ed22c5bc45, 0x1633b0fbd77d6d9d, 0xa57c267b6fba36db, 0xf94465fac0b899a2, 0x34a4be281ed17637, 0x000055d1bdd26591}, 
{0x0c709286502b5ccb, 0xfda560011e994595, 0x4856e21b8eef3c44, 0xe6ff4b98a9ea2de2, 0x9887cbbdfb34929f, 0x7e47e75497b06b9b, 
 0xe723e79aba5d9470, 0x02c05c07824b8e6e, 0x5e4e45149e3c5445, 0x2452ae29e3055ea4, 0xef90de3635f81ed5, 0x00002811146405a3},
{0x9807214a3a1c1cf3, 0x7a0e708928e1f773, 0x6b79a82bec4dcc5f, 0xe98afbe2931e7695, 0xf1bfaf7f0d6fe513, 0x729355b40cc74834, 
 0x7355193adf5fc317, 0xaabe07a1788cb696, 0x22d720814db72b6b, 0x37df09e734de45ba, 0xfd056fda4f240cba, 0x000068abbb7b5c8e}, 
{0xc3777b85da951b35, 0x729e2ee622cb06ce, 0x142662ca9f3ec02b, 0x79b13bb964738d59, 0x0d0d82aa614f52ff, 0x2073598189b312ef, 
 0x187d2fb5ff497e99, 0x55fea80cef2a4b0e, 0x6b197f79d5faf833, 0x254447c18292f844, 0x60f938b568ee1543, 0x0000071826a2adca},
{0x9c02260c68b4dbcd, 0x0ead5b56bfb777be, 0x3bc3be5177278fd6, 0xdab6622b90cd39de, 0x90cc3ec6aca6ddd0, 0x6e158ff767ce5d2c, 
 0xa8b669d3ff7489ea, 0xaf133837592c7ada, 0xfbf80d62062ec026, 0xc3512d9a00005fbb, 0xb759f49e11d399a6, 0x00002b5bc9341b5d}, 
{0xc32617fb97a7ba46, 0xdc97c62323c3a3a3, 0x100c4c10f8ad3eb2, 0x303659a310a3583d, 0x12da436e2f3f2e72, 0x4d50f367a011a161, 
 0x8328c3f9f44a3084, 0xf982c9da22658656, 0x5eb7238a18dd90a7, 0xb9156e1d1b343898, 0x57243ec083bfef2f, 0x000003de52126ef4},
{0xbbd06880c51c680b, 0x7a81a7c7078464c3, 0xfdecd7041b4ecf3e, 0x2c5c3d04ed2f2a03, 0x5d174a6a4e7f7db4, 0x1b52d2539d1ea2e8, 
 0xa5cc20018839ab95, 0x67625d02ae4cf980, 0x186074dcbd384821, 0x9e5e42872a3c7a83, 0x545832703a5a56b9, 0x000027681cf8d9fb},
{0xd629bc89002bccea, 0xb88d005e2c3a8f32, 0x56386d851d5b66d8, 0x60ed69d4abc2ee09, 0x1731219ec24a5538, 0x966d87bcf622ea5d, 
 0x62a6b07e4c8b3cef, 0x6ea16f4b509b81a3, 0x7a97d35b5cde162d, 0xe25fb4acf2af1e4f, 0xc48e64140bd3474e, 0x000021fdd6c8fb82},
{0x9288477180a6c951, 0xb2d2de965a033d61, 0x3ba1694ab827311a, 0x70a5b57fc1c70cdc, 0xbfd11385625a2e5b, 0x2dddafb04a38853f, 
 0xf21823ff1b225fdc, 0x5f007a2e1641aeb8, 0xc3e5684ac220ecaa, 0x78179af27dd10f63, 0x96dc98f67c36644f, 0x000007d6d89bb770}, 
{0x829327c9d19d0226, 0xd65d25dc7c2e4992, 0xd5dbe128d0a23ba2, 0xf6dfc62fd21334a4, 0x651eaeb5c3a9a583, 0x180c253598055eb9, 
 0x3f73fa2eef9168fa, 0x4318bbee307725d0, 0x54dd26a9fc5450f7, 0x76aba5758680dba0, 0x353ed351a6a5f735, 0x00002ff3a6573de4},
{0xb9993936aa2301f8, 0x7b319eace5e9b127, 0x012e616bd697ba4e, 0x811b1f35f96913b0, 0x474db18b6ab00c82, 0xc1fff493fe2c0901, 
 0x796424d7a11aede9, 0x61076638d85c4c48, 0x64774660a3be93d0, 0x43fa3f433b9d067d, 0x47a0b426f92f7600, 0x00000a280ae8d170},
{0x3581912de993f071, 0x70141cffc8a2ecaf, 0xc3eb4b7d9eaadf4d, 0x39e0d5685c6769f8, 0x44208a1289b360a9, 0x1495f58b3248d82b, 
 0xcbc66bb98cda2e99, 0xcc3f8763f217fa81, 0x495812161e7d7e11, 0x255fa1a2a5d70135, 0x240f5a6f7eae5ba4, 0x00004c1f4dd638f5},
{0x5b9845dd9a79003d, 0xef65f03c8f56ecbd, 0x30f64ff52b455d62, 0xd45579863fad5d92, 0xc798cd9c72eb564d, 0xdd15c4f63ed0d645, 
 0x9f35ec5bcf419520, 0x2759d2cb3306dfb3, 0x6a4cee0c84723002, 0x62ae428e1405808c, 0xa93787ce06a12315, 0x00004885205a0a7f}, 
{0x3184f5ff10fc6af3, 0x143b921a36e08bdc, 0x4da6a729b2406bf7, 0xe6678bf19eef357a, 0x96091214f1c2f4a2, 0x9f07e61747e02986, 
 0x48fa86d281046604, 0xff69050dd5e29481, 0xf97f744ab920445e, 0x16b828177fe35d68, 0x2a44107c12a0c668, 0x000065cd488721ca},
{0x4e5420f1827b439d, 0xf487a4ed360b1c4d, 0xc55efc7f8d8112d0, 0xed67a91dbc5910c6, 0x9e9a78efa44fc34f, 0xd40f65d4211d8623, 
 0x5c21f3f0fe48dbc9, 0x09cea4a83954032f, 0x068a443a160ccf02, 0xba2d35302646dabe, 0xb27cc0aad03ba372, 0x00002e3f49905a08}, 
{0x40785de28d4c9530, 0xa6405c1c01e10071, 0x3c209f250c73b2c8, 0xbf22e6ebadc20a64, 0xd1ddab04af2ab602, 0xa33c04772868d58c, 
 0x98da3ce309d547da, 0x4dd504f6f173d486, 0x283b355d938c1316, 0x99001a20441ba13a, 0xe8c99ec8d3bb4b46, 0x000006f688bd1c61},
{0x459a64577f98dd28, 0x3fd6890b60aa7022, 0x32b84ab229b33d20, 0x7ca6e1524f6ebf03, 0x4f0242dd469a4d8b, 0x53eaa4c1ebc77c19, 
 0x62c19f1c435ac30d, 0xf230ae4e1f1bf94b, 0xcf7e083e29c16d7e, 0xca42c2833b78234e, 0xd01effd11db566a8, 0x0000224e1f2ffd2e}, 
{0x6edaa71406539762, 0xb74f189440621eb1, 0x345f3262ec4f13e0, 0x23185407a289e9fd, 0xd105feb3ed85cec2, 0x11f70813d04e49fc, 
 0xd99654fecb39ab46, 0x734ecf9475139205, 0x54e95c9bd579aed5, 0xe044d2c9270c1251, 0xe60cafcea4bb3508, 0x0000552b57bca931},
{0xd91b6c9b924d91b6, 0x9b924d91b6c9b924, 0x91b6c9b924d91b6c, 0xb924d91b6c9b924d, 0x1b6c9b924d91b6c9, 0x312d91b6c9b924d9, 
 0x17d193651e9dca60, 0x8df224d4272ec01e, 0xcbd2bc92a7a778f6, 0xa59cf2b6356cd90e, 0x9c712eb8f35468fd, 0x00005c2c61931f7c}, 
{0x249b236d93724969, 0x6d937249b236d937, 0x49b236d937249b23, 0xd937249b236d9372, 0x9b236d937249b236, 0x7d4249b236d93724, 
 0x6f78bf6586101fb3, 0xdeba77a01ff372b9, 0x2809bf0c10d132ca, 0x15e12e137474b550, 0x32e144163d1a7a6c, 0x00000083bcb784fd},
{0x0a014e250439995f, 0x45fc65f1fff85333, 0x6bcb9b2f717ec6b4, 0xe17f29c4a3aab256, 0x84007f11103dbaf3, 0x8f00a6a9f3a093f6, 
 0x9726358a43891d51, 0x0897a6562e06b392, 0x9c43741cf4f314b9, 0xf134466de6efe2ab, 0xf564982d2c7fd077, 0x00001314c36f69c9}, 
{0xa43641b1d7cedc7d, 0xf0874e7045509b0d, 0x792e7b86ff0d73e7, 0x7b8ec819e2656382, 0xdb846de5527f9573, 0xcbaed11fbdc7b5a7, 
 0x9cf8b6f734116414, 0xab4016ed22d2b78c, 0x901482b46aac884d, 0x6f313d2d60b58e49, 0x8226ce453aff56f5, 0x0000541b0694e059},
{0xe39251fb5f896dd7, 0x861156adc66bf25b, 0xd3b6e410c9eb77f6, 0x0149a5b2e22c5ff6, 0x39bf19b234bc83fe, 0x6fc6ddcde9500c15, 
 0x33d635192e7ca410, 0xf40bb7c04811efe5, 0xb95bdbad0678f5e3, 0xffee8ddd2907e2da, 0x71bb095c5885e70a, 0x00003006b1c7034e}, 
{0xd681eed8b087dac7, 0x90726086fb0a1d9f, 0x643ad6038fe15ff2, 0xf6524ccdfeb45ce0, 0x511bd3aa0b479432, 0xfdaa3b25b585a917, 
 0x16c0ca87eb477009, 0x5dcad9871abb0038, 0x5ba46393deec08b5, 0x9ac8a0b793849197, 0xa8f7feda5fa4ea5a, 0x00003a742cc9deb9},
};


const uint64_t v_3_torsion[20][2 * NWORDS_FIELD] = {
{0xD89D89D89D8A493E, 0x9D89D89D89D89D89, 0x89D89D89D89D89D8, 0xD89D89D89D89D89D, 0x9D89D89D89D89D89, 0x8B389D89D89D89D8, 0xB4C6B9529F01D8C3, 0x1399AE2626262260, 0xDE85321D9D8185DF, 0x8451DC3FDF91784A, 0xFAEFD5E487381389, 0x6319EE6373CB,
0x3B13B13B13B1248D, 0x13B13B13B13B13B1, 0xB13B13B13B13B13B, 0x3B13B13B13B13B13, 0x13B13B13B13B13B1, 0x7A4B13B13B13B13B, 0xA30792A3BBCAECC7, 0x8E3262972F905537, 0x6EC1E1420B7BAD51, 0x3369C4F4190692FF, 0x9D6D588BD01A282C, 0x28F2E2C80A9},
{0x673D45AA630B09FB, 0x5673D45AA630AE95, 0x95673D45AA630AE9, 0xE95673D45AA630AE, 0xAE95673D45AA630A, 0xD4595673D45AA630, 0x06D7B45385F91ACC, 0x7FDE0F3B044702EF, 0xF1BFC4766FC2E18A, 0xD67138B8790E3167, 0x9EF75C6F0552A406, 0x2C5A25459904,
0xF6C4681424EE5801, 0xAF6C4681424EE5FA, 0xFAF6C4681424EE5F, 0x5FAF6C4681424EE5, 0xE5FAF6C4681424EE, 0x7FAFAF6C4681424E, 0x71E7F021FC96E1CF, 0xBD317223E4665091, 0x04D1B06EED834E4E, 0xF423F47B02EEF4B8, 0x0A418B4D55C23C88, 0x94F95559E31},
{0xBC8EA75EFC1DB814, 0xDC562840F895B742, 0xEA75EFC1DA922F50, 0x62840F895B742BC8, 0x5EFC1DA922F50DC5, 0x1B3895B742BC8EA7, 0x0EF4E35288013377, 0x7034C1EDC7954F9D, 0x404E07FFDCD9C4B4, 0x6C0D3C3112E9FC8B, 0xE93593735AD57C40, 0x5E74FB7D527D,
0x5C835ABF61CF41ED, 0xDF2950278C2E9C12, 0x35ABF61CF458FB68, 0x950278C2E9C125C8, 0xBF61CF458FB68DF2, 0x7E9C2E9C125C835A, 0xCA8064284EDAE000, 0xB011CE81CE7860C5, 0xF2D3F4033A9B8AE2, 0x2FF7880A1DE06DD0, 0x7182DD9DC3FCB499, 0xA4A77D973AB},
{0x8AE21EF6EA938B09, 0x37966C6ED5186501, 0x69DCB18F74253FB3, 0x3188241B31A56443, 0x09156C7D752C811D, 0x9CFAE79AFE751DE1, 0x8BF44341193A82F9, 0x34DAFBE7EE16D274, 0x0272F0852BA272D8, 0xA0F247E8810D0FE5, 0x48E124BE4CC4D188, 0x4FDE2C9A5389,
0x44369DCB18F7403C, 0x11D3188241B31A56, 0xDE109156C7D752C8, 0x993912AE79AFE751, 0x34E708BDAC04CC86, 0x8C7E4CE5A9BBC962, 0xF269836E4C98DDD3, 0x045188E7965A38A0, 0xDAB83EB832EB62A0, 0xCCEFE1931E93559A, 0x775966B73B29F6D5, 0x45DBC312B900},
{0x0B71EE1F7F5C9327, 0x8A5569830CE94076, 0x12961C17A5932157, 0xDD79C7E8EBB6086B, 0x2BEF8AB644F43951, 0x37277CB68D98CE33, 0xDE633F0A815B7506, 0x61740E19C3F2EFA4, 0x61B1E49FB5E4EABE, 0xA015247782FF386E, 0xE25E2C7B9F068D08, 0x5A5611C2C7A3,
0xD213F53791E68D00, 0x2EDE2F635D1EFA2E, 0xDA72EC5F8871204D, 0xDAEBFEACFFF3E491, 0x5F948C8E72BBF1CF, 0x4A440214B6EE743F, 0xD224FC96C70931D9, 0xEA00C3F488138831, 0x9D46231784C01FDC, 0xB12AA781AEC3B474, 0xE312A59BD123CE5A, 0x1FED35710EB4},
{0x72F7284A69378371, 0x03D4A5A89547E058, 0xB12975E3DAE2E152, 0x599E71CBADA705F9, 0x4ACD0B0B6F42CE9A, 0xE5285A0245577966, 0x6C038D909BB02FA1, 0x124374A6F770AF89, 0x99103DFE37CA79AF, 0x147E8A248FDBCAAE, 0xEB9B0A578010CFB9, 0x37F0B3678B6F,
0x5D470CF2D274DD99, 0xC8516258CB0C2B2B, 0xB43C53B94E11D2A6, 0x5ABE2DE626199F2D, 0x029D6C7C473EDC98, 0xE0376A892583E1DC, 0xC0CAA571F277C6A0, 0xD4F6AD7F88406328, 0xC9A2779B2F2431FD, 0xD7757D28491C9C9C, 0x3710D688A0ED993D, 0x4ADB9FE768DE},
{0x81F1C30C09FD33FC, 0xDBF51DCE3A9149C9, 0xE9CF78A0524C35B8, 0xC02099DC646FDE01, 0xB0594156B5517D78, 0xCDF2CD6BD4510E26, 0xA62E43C6D4ABA685, 0x06282F81A9AB8658, 0xD6D76B986C3AFC2D, 0x82003479185AC489, 0x68A227ED5A5D8D62, 0x4CB44C725522,
0x248D49A3572E2D8B, 0xD7958CBA82F9C02A, 0x8CAA9BD2ECD45A98, 0xD568F26B9E3F23BE, 0x6C2D5F812C90C433, 0xF1565E72D2FCBB81, 0x27E816D21960503D, 0xC557356BF112F986, 0x4C0F35DCE29E0B8B, 0xB5D66BBE22866AEA, 0xA93F73DFFDAB2E0A, 0x615CF5C957D3},
{0x516EE2A1BE021E2A, 0xF602D6E151658AD7, 0x26B24FB3189298B0, 0x0D965FAF4CE85C95, 0xEFEF3DB9B3A4B775, 0xD851DD3FA8E08D31, 0x2DA32E186C78CE68, 0x143617DD482EE422, 0x667237E94436FC75, 0x1AC3465D96DCFDBB, 0x56D74ABF63E8D5D3, 0x5D7C60C0D2E4,
0xA30146117F0077FD, 0x9BE366E0CADBC188, 0xEF64080B2EACAD26, 0x0A8FD83BF0D513C6, 0x877CB3DDB56170B2, 0xB35C3C73A225B6FC, 0xBF79CBB465569B88, 0x498384E224080C8B, 0xB2F0B94988649443, 0xB3DCD435A017EB4F, 0xE9941938991157FB, 0x21C1C22E5E5B},
{0x0D40E007BD838CEA, 0xA6EFBD2F6C46FEC8, 0xDC1072B787D7CD36, 0x7204C616DD691C29, 0xF3C600AA941422BD, 0xB810967F5BD8F3A2, 0x53CCFBAE4D3DD147, 0xCC071945DE01CFF7, 0x6DD53CCD52E214A3, 0xB2C2FB56192E2E38, 0xD2B99B61C093CFD5, 0x51BE0034F0EA,
0x8107763EA961F872, 0x74B86F2CE50392D0, 0xDB4527F030D9F82D, 0xEC3F66A797FB122F, 0xF4DE67CF2F609807, 0xEFC422F586A5B1F2, 0xB765C11D7152D2E1, 0xB0A5BFC4FD2AC62B, 0x589DF808D4BB351A, 0x1165BA9E7035FA93, 0xE9B487C366AEC785, 0x586D2918F33C},
{0x6E3302C6FE0C0C01, 0xDFAC66DC6CEDA28C, 0xDED64C5EF280083F, 0x8B39B4C197F785CD, 0x11B93A8C64FD9206, 0x9AC84CC06813FCFF, 0xCF85682DC9D9B864, 0xC23496D96970C301, 0x5194BE86F6E26D90, 0x4DB579722DE163E0, 0x66DAEB4660E533AE, 0x15B525F2A541,
0x7C758374FFD93EC3, 0x2C7354CAF23E0942, 0xBD93A801DBC916D7, 0x47E4D764786D5DAC, 0x0712497FC82C0471, 0x87311F4B3AF3FE32, 0xEFAEC8155C91650E, 0xE2169C5AD02053FE, 0xC96489E29375ADEB, 0x5E7D1381050F03CE, 0xB88C1A56DDD05F31, 0x6070D9E2F41},
{0x9ED7073D4D892D5E, 0x7A8ACF5D59CC31D7, 0x149DB0BEB6B3A2E1, 0xC059D51CC46D3357, 0xEE43544B33B041DD, 0x5CC5EB8BC024538F, 0x4B759EA5B9EAB631, 0xA335C8BC0AEEAFBC, 0xB03F67E326524765, 0x2C790108FA72A4B0, 0x789B5DA805C4192F, 0x64DEC5C9AB82,
0x36DAB776C6A6E1AD, 0x70788D740F12BB16, 0x0678109B1BC9AEB8, 0x6CC747669CD9ABEF, 0xCBF25E90DDFDB9BA, 0x9186ABE61B8B423E, 0x29E06834AA38279D, 0x45176543D221EEC1, 0x761F084D3249B19E, 0xB968904364D0E464, 0x5DB85DA70B052289, 0x521E2DDB50A5},
{0x395783F790D29774, 0x112CEC9A5FB0FD8E, 0x2286B13D7C636B50, 0x3BB1C1FAABC848AE, 0xCEBD9A801EAB03DC, 0xD0D0F3042DC47BD3, 0xBA7CC91C76FBFC6F, 0x7E4B81D9BC252CC4, 0x791DA3C97B45B52E, 0x76E4B2A8663A7CDB, 0xB18F9D7CDF16DE77, 0x6738B89E9A90,
0xC5C400C8DEF67ACF, 0x7DB5C96374C369C2, 0x4DE65F1497C0251B, 0x3D6A0B0AA5A7DC1D, 0xCFF42CDA41FF0694, 0x13585BF9A20DF747, 0x29F5EA2387657EA2, 0x85F982D144BC9D02, 0x70BA26172B51F920, 0x7CDC5B7AD3069E68, 0xDA452B30229CE4DE, 0x5308C36EA06B},
{0xAC4F402D28A1B7D9, 0x1F9692D5D204DA19, 0x7B09C49F36556C65, 0x74E03DD0CC93BAA4, 0x2857AF2E2C697F78, 0xB5B97969D9A74314, 0x9B0B4C1B8B9C5804, 0x012FE23955636F0E, 0xB8E8FEC4456834F9, 0xF6E7C5B893C1F2AC, 0x05A45A12C0CF9B64, 0x4242B7D98CD1,
0x895BC47E5E99FE58, 0x00CFD306BF78ED7A, 0x43394EBA61FCD38C, 0x83E94C74E7C77585, 0x9E944616E2627346, 0x9BA6856CF3432676, 0x2185C6AFF5533077, 0x67F7CB233436A703, 0x52D795D168AD54FF, 0xBB7BF59763DC0670, 0x79561A9B5335EFFB, 0x6F8E14E2EA1D},
{0x52170E4682673A4B, 0x0AD4577028668C00, 0x105830C4E5B35043, 0x0E44B518DCE2097C, 0x1DC57628AFA086C9, 0x7017D10868A9652D, 0xF52DAC7D308B4DED, 0xE5F8D6B44798B8A4, 0x860E5513916A8B0B, 0x0EF1A2AE69403037, 0xFD7E1676F8DB8D34, 0x1DA40260AF34,
0x438DF92CAED981E9, 0xE0EC927187AF9BD2, 0x02C47A2EB752165A, 0x10A814019E74674B, 0x0AD43DCF5C2393FE, 0x9EF40A6C20918C14, 0x827A35EE6A2A622C, 0xC5367CAADECCABBA, 0xDEC9E5F60CC017A0, 0x89393E2776CC5F44, 0x7AD261CF40C946E0, 0x69EC298FC2C5},
{0xE370D28A643127FE, 0x6484E527E4F15551, 0x3F59642BD5A34627, 0x85A03E71ECC4BDC1, 0x7B2E731CBACBC6B9, 0x70F5FDBD8FDA90B6, 0x24E12F3C9683795B, 0x35FAA7C6879A3C7C, 0xFF53C1E88A24C6E7, 0xE5DD61BDDC562FD5, 0xE68B1C39660B3261, 0x6259E2A86D74,
0x2982F0136CCDEF7A, 0x8848824CB25EDE31, 0x7BF8BC5D9CE7B4CD, 0x5A3A0205A555D497, 0x9240434A161CAB24, 0xFDB3CBB75FE9869F, 0xC97131D9A60D18C9, 0x9DB915412B8CB0B8, 0x5B7E4834AD58F24F, 0xDF6E9178CA871824, 0xF1259454624AC092, 0x1327C8999EB4},
{0x666280546751F204, 0x3124828432952042, 0x628126D710FA6B0A, 0x1D3B96F1B28EB258, 0xA3E698E6B79C0621, 0x5CFD4588D9A09890, 0x43A7B8C256D49EBA, 0xE2F94301C0032B74, 0x8953956AC6CA7C77, 0x7F8015DC765F106C, 0x82E4DDDD36ED8083, 0x133AE4EA2F71,
0xDBF063D1F1AF17B9, 0xCEC32E934E871629, 0xE2671C831AFAA693, 0x960B975DBBED5813, 0x203E4A33C527B48A, 0x423CD368EF5C02DB, 0x361633B23B9CEB74, 0x5F11CA4E0B5ECBDD, 0xAD9328EC4662A397, 0xEA2509539AEEDDBA, 0x15BB2346F14D8146, 0x2F2B9A05EEE},
{0x795D912BDEF015D7, 0x65E6C0F35599987E, 0x8BE785422F397093, 0xCD93F70F07BAA7DB, 0xF1A8945586B3C277, 0x26353E447C9BF58B, 0x4CD879A487B985CA, 0x9E680A1F08FF3F3F, 0xEA67CD5F51356E12, 0x501DDEE09936B7D1, 0x559A868F99683C3A, 0x23FA0B67D681,
0xEDDAB05F06B5A605, 0xC6E7FE44E0E20ACE, 0xDA2D7FCAF5C0C0EB, 0x7507BC508BE5F429, 0x7516F14BC559D8F0, 0x55DB0692A07CC717, 0x12F7611288A3B08B, 0x34ED3DD86C14B639, 0x2BCFE7EA6234CAAA, 0xA20E37F49CD7B313, 0xED785E90CA869C5F, 0x524FB4A9B68D},
{0xB24323DEA264A910, 0xFBB77EB1969BA34D, 0x06DFE6BD2DF0E62D, 0x4BA1D9212AAC1737, 0x6604456CC168CE0D, 0x1F045C2902E70B1A, 0xC30F3CF005747BBB, 0xD0808A1E60231D09, 0x616E5202B8B68AB9, 0x91279DE1E1F59C61, 0x17039A54DE74E351, 0x483F7B722965,
0xCA63AE6778B0F84E, 0x3920204D38EBDF19, 0xFB1FE6BAD523F1EC, 0x8B34EDE136AC2733, 0x7409325BA76B71BB, 0x987FACF98158EF9B, 0x3EBAB81D7CC6988B, 0x518A2D688F371575, 0xC77B4766A9D72BCA, 0xAF7343FE6E77A7C4, 0x54516072DE9FE449, 0x52E493B8BEDC},
{0x95B9273E98BEE101, 0x6CF2C2CC7C2F0D29, 0xEFE3B76E594AA11B, 0x3DDEDCDD1FE42241, 0xF7E15F986E39CC89, 0x3CF9E152B6FD333B, 0xE7F2CF0844AD69DD, 0xB792DFF3C762D02E, 0x3888F4A332FD9030, 0x8A4CC0E4C437575A, 0x833E2BA7BAF41403, 0x135FE5EBD4BB,
0x657D9769E52DAD91, 0x84951CC10B514173, 0x7678CDEC0CC5511B, 0xD4E7DB99FC763848, 0xC6ADD473DF8087CE, 0x842DE2D06829FA76, 0xD086DB2A4651BE48, 0xD0399255E5DAD344, 0x6B2EAEB21B8BB524, 0xF6DE9148F0694AEF, 0x5A85093194755805, 0x2570D86C9FCF},
{0xD665CD614A703CBD, 0x7251A4FFE04E2B30, 0x8AD6A13EAA0B07BC, 0x2AB5112D91260BE2, 0xF31D78441E75FDE5, 0x981D1D465A8768E6, 0x7AD08CCEE352CCDD, 0x31C6C60ACD409AC7, 0xDFC10AD642C330AA, 0x16DA3C495AE40C44, 0x89AB4B294D700C6D, 0x13081265A555,
0xB649623190FAD2EC, 0x9E0A9F4A626C11FD, 0xEF8A6A8092D66371, 0xEB9370EA38CC1EED, 0x74BF8D8667FFF12C, 0xF931EE21E90FE5CA, 0x5E180EC10EC59AE0, 0xBA6729A7EF221E52, 0xAEAB0D0AC6ED85F9, 0x2401EAF62859B015, 0xD309B49CD60C1B34, 0x2CBA9B452CC8}
};