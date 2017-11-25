/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral 
*       Diffie-Hellman key exchange.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: supersingular elliptic curve isogeny parameters
*
*
* Modified by Geovandro C. C. F. Pereira (geovandro.pereira@gmail.com) 
*********************************************************************************************/  

#include "SIDH_internal.h"


// Encoding of field elements, elements over Z_order, elements over GF(p^2) and elliptic curve points:
// --------------------------------------------------------------------------------------------------
// Elements over GF(p) and Z_order are encoded with the least significant octet (and digit) located
// at the leftmost position (i.e., little endian format). 
// Elements (a+b*i) over GF(p^2), where a and b are defined over GF(p), are encoded as {b, a}, with b 
// in the least significant position.
// Elliptic curve points P = (x,y) are encoded as {x, y}, with x in the least significant position. 

//
// Curve isogeny system "SIDHp751". Base curve: Montgomery curve By^2 = Cx^3 + Ax^2 + Cx defined over GF(p751^2), where A=0, B=1 and C=1
//

CurveIsogenyStaticData CurveIsogeny_SIDHp751 = {
    "SIDHp751", 768, 384,         // Curve isogeny system ID, smallest multiple of 32 larger than the prime bitlength and smallest multiple of 32 larger than the order bitlength
    751,                          // Bitlength of the prime 
    // Prime p751 = 2^372*3^239-1
    { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xEEAFFFFFFFFFFFFF, 
      0xE3EC968549F878A8, 0xDA959B1A13F7CC76, 0x084E9867D6EBE876, 0x8562B5045CB25748, 0x0E12909F97BADC66, 0x00006FE5D541F71C },                                                
    // Base curve parameter "A"
    { 0 },
    // Base curve parameter "C"
    { 1 },
    // Order bitlength for Alice
    372,
    // Order of Alice's subgroup
    { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0010000000000000 }, 
    // Order bitlength for Bob
    379,
    // Power of Bob's subgroup order
    239,
    // Order of Bob's subgroup
    { 0xC968549F878A8EEB, 0x59B1A13F7CC76E3E, 0xE9867D6EBE876DA9, 0x2B5045CB25748084, 0x2909F97BADC66856, 0x06FE5D541F71C0E1 },    
    // Alice's generator PA = (XPA,YPA), where XPA and YPA are defined over GF(p751^2)
    { 0x9A36B39572AFB363, 0x401FFC738B03A49E, 0x747C146775C0267A, 0x5C0BE072950D16CA, 0x52828FF50C3F7B75, 0xF207FCF3CDD26736, 
      0xD46563F042FA06B9, 0xABE5C0FFFCBE6E1A, 0xC6E375DA69B0682C, 0xDF2E7F0D55761363, 0x9531CB890FC5EC66,     0x54921C31F0DC,
      0x3AD752CDCD73BF66, 0x3BEBE649C18101F0, 0x57C6D43B799811A6, 0xA1DBAD8CA47BB7E7, 0x44D652EFC4729178, 0xF7852B7DF02C3348, 
      0xBA1A177500E9EB5A, 0x86B6D4A9B751797C, 0xCCF63DFE623092AC, 0x633C4E97AB4FF118, 0x01993137A5B63D6E,     0x28849BC0D81E,
      0x03EB1046A1A04383, 0x96FBC8EF189D995A, 0xCC62805345C718D2, 0x763EC81DE3FCA109, 0x77DCA408BFB41C6E, 0x0CCF4C81A0A02B12, 
      0x6FE154D761EDEBB6, 0x656FC617A7E24FFA, 0x9F71A590F52D32BD, 0x5EC56C396D03EE18, 0x31D7E97D634413A3,     0x5684BB6984A9,
      0x98F4A768CDD52BE2, 0xEA3B1B7702B22A08, 0x521E5B3EC4F6084E, 0x52AD923A5C998B6F, 0xF617206FB5C2A8B3, 0x9599748242EBD7E0, 
      0xC09CF7E35DAC198A, 0xA907FE3CAC37249B, 0xA24E3A24813B36DD, 0x9DD6D5F7CD5CC90F, 0x7149B9148814744B,     0x62AB14A78F46},
    // Bob's generator PB = (XPB,YPB), where XPB and YPB are defined over GF(p751)
    { 0x76ED2325DCC93103, 0xD9E1DF566C1D26D3, 0x76AECB94B919AEED, 0xD3785AAAA4D646C5, 0xCB610E30288A7770, 0x9BD3778659023B9E, 
      0xD5E69CF26DF23742, 0xA3AD8E17B9F9238C, 0xE145FE2D525160E0, 0xF8D5BCE859ED725D, 0x960A01AB8FF409A2, 0x00002F1D80EF06EF,
      0x91479226A0687894, 0xBBC6BAF5F6BA40BB, 0x15B529122CFE3CA6, 0x7D12754F00E898A3, 0x76EBA0C8419745E9, 0x0A94F06CDFB3EADE,
      0x399A6EDB2EEB2F9B, 0xE302C5129C049EEB, 0xC35892123951D4B6, 0x15445287ED1CC55D, 0x1ACAF351F09AB55A, 0x00000127A46D082A },
    // BigMont's curve parameter A24 = (A+2)/4
    156113,
    // BigMont's order, where BigMont is defined by y^2=x^3+A*x^2+x
    { 0xA59B73D250E58055, 0xCB063593D0BE10E1, 0xF6515CCB5D076CBB, 0x66880747EDDF5E20, 0xBA515248A6BFD4AB, 0x3B8EF00DDDDC789D,
      0xB8FB25A1527E1E2A, 0xB6A566C684FDF31D, 0x0213A619F5BAFA1D, 0xA158AD41172C95D2, 0x0384A427E5EEB719, 0x00001BF975507DC7 },
    // Montgomery constant Montgomery_R2 = (2^768)^2 mod p751
    { 0x233046449DAD4058, 0xDB010161A696452A, 0x5E36941472E3FD8E, 0xF40BFE2082A2E706, 0x4932CCA8904F8751 ,0x1F735F1F1EE7FC81, 
      0xA24F4D80C1048E18, 0xB56C383CCDB607C5, 0x441DD47B735F9C90, 0x5673ED2C6A6AC82A, 0x06C905261132294B, 0x000041AD830F1F35 },
    // Montgomery constant -p751^-1 mod 2^768
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xEEB0000000000000, 
      0xE3EC968549F878A8, 0xDA959B1A13F7CC76, 0x084E9867D6EBE876, 0x8562B5045CB25748, 0x0E12909F97BADC66, 0x258C28E5D541F71C },
    // Value one in Montgomery representation
    { 0x00000000000249ad, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8310000000000000,
      0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x00002d5b24bce5e2 },
    // epq_A = e_{2^372}(PA,QA)^(3^239), the reduced tate pairing on points PA and QA
    { 0x6F7867251527C203, 0x39B7914DE41522D8, 0xDBD5AFB1FBB1DF0D, 0x4FE548B941FE834C, 0x2D6DBC600480F7FE, 0x7E7D2D33D7DBF57D, 
      0xE4A46BC226A465FE, 0x8A034E0B9D916254, 0xE95978C4E0EF39C6, 0x8191F8B3F8D1D8AC, 0x5113FE158F94BF5C, 0x000028832AA5FC10,
      0xE61C1450BB9F84E7, 0x9369CFBDE846F5C0, 0x031E40E9808455C4, 0xE57E57E6E84D3C28, 0x5A2CA5078611519D, 0xE0EC45F46674F5B8, 
      0x459F8BE21D16762C, 0x2D64849372AEBBEA, 0xA1C51E01218B635E, 0xDA37329CB55DDF3B, 0x4193637DD42C95DB, 0x0000028F72C6BFBD},
    // epq_B = e_{3^239}(PB,QB)^(2^372), the reduced tate pairing on points PB and QB
    { 0xB17285030C2B0AC4, 0x1A144FAE647D188A, 0x14D0B4D9908870ED, 0xB974365AF13535D1, 0xB6EAFFC560632410, 0xB869D41BF1548D1C, 
      0x19C46E73AD34467E, 0x7ADD776E10C669B6, 0x879EEC949D72CF5C, 0xBB147D03BF60A882, 0xC47102295737F1A9, 0x0000346652514C25,
      0xB355008813E7590C, 0x7F4EC82FBC99767D, 0x05AD26F80596FFAC, 0x047D79569BE1DB79, 0x3C473D097FA0AB52, 0xCC751BA077A3E40F,
      0x9CD446900AFA3CA5, 0xFD066F914542BA41, 0x370DFC7776476116, 0x5C5E93685DC0887D, 0xDDA4F8B251500380, 0x00001047D2E98A8D}
};


// Fixed parameters for isogeny tree computation

const unsigned int splits_Alice[MAX_Alice] = {
 0, 1, 1, 2, 2, 2, 3, 4, 4, 4, 4, 5, 5, 6, 7, 8, 8, 9, 9, 9, 9, 9, 9, 9, 12, 
 11, 12, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 17, 17, 18, 18, 17, 21, 17, 
 18, 21, 20, 21, 21, 21, 21, 21, 22, 25, 25, 25, 26, 27, 28, 28, 29, 30, 31, 
 32, 32, 32, 32, 32, 32, 32, 33, 33, 33, 35, 36, 36, 33, 36, 35, 36, 36, 35, 
 36, 36, 37, 38, 38, 39, 40, 41, 42, 38, 39, 40, 41, 42, 40, 46, 42, 43, 46, 
 46, 46, 46, 48, 48, 48, 48, 49, 49, 48, 53, 54, 51, 52, 53, 54, 55, 56, 57, 
 58, 59, 59, 60, 62, 62, 63, 64, 64, 64, 64, 64, 64, 64, 64, 65, 65, 65, 65, 
 65, 66, 67, 65, 66, 67, 66, 69, 70, 66, 67, 66, 69, 70, 69, 70, 70, 71, 72, 
 71, 72, 72, 74, 74, 75, 72, 72, 74, 74, 75, 72, 72, 74, 75, 75, 72, 72, 74, 
 75, 75, 77, 77, 79, 80, 80, 82, 82 };

const unsigned int splits_Bob[MAX_Bob] = {
  0, 1, 1, 2, 2, 2, 3, 3, 4, 4, 4, 5, 5, 5, 6, 7, 8, 8, 8, 8, 9, 9, 9, 9, 9, 
 10, 12, 12, 12, 12, 12, 12, 13, 14, 14, 15, 16, 16, 16, 16, 16, 17, 16, 16, 
 17, 19, 19, 20, 21, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 24, 24, 25, 27, 
 27, 28, 28, 29, 28, 29, 28, 28, 28, 30, 28, 28, 28, 29, 30, 33, 33, 33, 33, 
 34, 35, 37, 37, 37, 37, 38, 38, 37, 38, 38, 38, 38, 38, 39, 43, 38, 38, 38, 
 38, 43, 40, 41, 42, 43, 48, 45, 46, 47, 47, 48, 49, 49, 49, 50, 51, 50, 49, 
 49, 49, 49, 51, 49, 53, 50, 51, 50, 51, 51, 51, 52, 55, 55, 55, 56, 56, 56, 
 56, 56, 58, 58, 61, 61, 61, 63, 63, 63, 64, 65, 65, 65, 65, 66, 66, 65, 65, 
 66, 66, 66, 66, 66, 66, 66, 71, 66, 73, 66, 66, 71, 66, 73, 66, 66, 71, 66, 
 73, 68, 68, 71, 71, 73, 73, 73, 75, 75, 78, 78, 78, 80, 80, 80, 81, 81, 82, 
 83, 84, 85, 86, 86, 86, 86, 86, 87, 86, 88, 86, 86, 86, 86, 88, 86, 88, 86, 
 86, 86, 88, 88, 86, 86, 86, 93, 90, 90, 92, 92, 92, 93, 93, 93, 93, 93, 97, 
 97, 97, 97, 97, 97 };
           

const uint64_t LIST[22][NWORDS64_FIELD] = {
	{ 0xC4EC4EC4EC4EDB72, 0xEC4EC4EC4EC4EC4E, 0x4EC4EC4EC4EC4EC4, 0xC4EC4EC4EC4EC4EC, 0xEC4EC4EC4EC4EC4E, 0x7464EC4EC4EC4EC4, 
	  0x40E503E18E2D8BE1, 0x4C633882E467773F, 0x998CB725CB703B25, 0x51F8F01043ABC448, 0x70A53813C7A0B43A, 0x00006D56A7157672 },
	{ 0x276276276275B6C1, 0x6276276276276276, 0x7627627627627627, 0x2762762762762762, 0x6276276276276276, 0x6377627627627627,
	  0x2F25DD32AAF69FE5, 0xC6FBECF3EDD1AA16, 0x29C9664A396A6297, 0x0110D8C47D20DEFD, 0x1322BABB1082C8DD, 0x00000CCBE6DE8350 },
	{ 0x093B97EBDB11A7FE, 0x5093B97EBDB11A05, 0x05093B97EBDB11A0, 0xA05093B97EBDB11A, 0x1A05093B97EBDB11, 0x6F005093B97EBDB1,
          0x7204A6634D6196D9, 0x1D6428F62F917BE5, 0x037CE7F8E9689A28, 0x913EC08959C36290, 0x03D1055241F89FDD, 0x000066963FEC58EB },
        { 0x98C2BA559CF4F604, 0xA98C2BA559CF516A, 0x6A98C2BA559CF516, 0x16A98C2BA559CF51, 0x516A98C2BA559CF5, 0x1A56A98C2BA559CF, 
	  0xDD14E231C3FF5DDC, 0x5AB78BDF0FB0C987, 0x168ED3F1672906EC, 0xAEF17C4BE3A425E0, 0x6F1B34309268385F, 0x0000438BAFFC5E17 },
        { 0xA37CA5409E30BE12, 0x20D6AFD873D163ED, 0xCA5409E30BA70497, 0x6AFD873D163EDA37, 0x409E30BA7049720D, 0x7013D163EDA37CA5, 
	  0x196C325CFB1D98A8, 0x2A83CC98457F6BB1, 0x157AA4649C505D94, 0x556B2CFA3ED1E977, 0x9C8FB301D3BE27CD, 0x0000659B5D688370 },
	{ 0x437158A103E247EB, 0x23A9D7BF076A48BD, 0x158A103E256DD0AF, 0x9D7BF076A48BD437, 0xA103E256DD0AF23A, 0xD3776A48BD437158, 
	  0xD4F7B332C1F74531, 0x6A60D92C4C627CD9, 0xC8009067FA1223C2, 0x195578D349C85ABC, 0x24DCFD2C3CE56026, 0x00001170D9C4A49E },
	{ 0xBBC96234E708BFC3, 0xEE2CE77DBE4CE5A9, 0x21EF6EA93828AD37, 0x66C6ED51865018AE, 0xCB18F74253FB3379, 0x6231B31A5644369D, 
	  0xF1831316FD5F9AD5, 0xD64412327D9D93D5, 0x2D9659AFA40085D6, 0xB872D3713E1F01AD, 0x96B929E85C90E590, 0x00002A0A122F3E1B },
	{ 0x751DE109156C74F6, 0xC86993912AE79AFE, 0x96234E708BDAC04C, 0xCE77DBE4CE5A9BBC, 0xF6EA93828AD37EE2, 0x51B51865018AE21E,
	  0x57F8534430BDF5AF, 0xA5BA9F3225E0FA02, 0x05DBA7E2AB49759E, 0xE4706D1BDBA54763, 0xC5316BE14AF60ADD, 0x00002007A8A7A392 },
	{ 0x2DEC0AC86E1972FF, 0xD121D09CA2E105D1, 0x258D13A0778EDFB2, 0x25140153000C1B6E, 0xA06B73718D440E30, 0xA46BFDEB49118BC0, 
	  0x11C799EE82EF46CF, 0xF094D7258BE44445, 0x6B087550522BC899, 0xD4380D82ADEEA2D3, 0x2AFFEB03C6970E0B, 0x00004FF89FD0E867 },
	{ 0xF48E11E080A36CD8, 0x75AA967CF316BF89, 0xED69E3E85A6CDEA8, 0x228638171449F794, 0xD4107549BB0BC6AE, 0xB7888349726731CC, 
	  0x0589577AC89D03A2, 0x79218D005004DCD2, 0xA69CB3C82106FDB8, 0xE54D908CD9B31ED9, 0x2BB46423F8B44F5D, 0x0000158FC37F2F78 },
	{ 0xA2B8F30D2D8B2266, 0x37AE9DA734F3D4D4, 0x4BC3AC46B1EE2D59, 0xA541D219D9E660D2, 0xFD629383B8C12367, 0x0E789576DA7C1E23,
	  0x2321F1135780B208, 0x059EED9A8BB7694E, 0x3EAC20CCA7C7B679, 0xADED37DC1395BAAB, 0xD701BA16F6CD4328, 0x0000250A355A8E3D },
	{ 0x8D08D7B596C87C8E, 0xFC2B5A576AB81FA7, 0x4ED68A1C251D1EAD, 0xA6618E345258FA06, 0xB532F4F490BD3165, 0x0987A5FDBAA88699,
	  0x77E908F4AE484907, 0xC85226731C871CED, 0x6F3E5A699F216EC7, 0x70E42ADFCCD68C99, 0x2277864817AA0CAD, 0x000037F521DA6BAC },
	{ 0xDB72B65CA8D1D274, 0x286A73457D063FD5, 0x7355642D132BA567, 0x2A970D9461C0DC41, 0x93D2A07ED36F3BCC, 0xFD59A18D2D03447E, 
	  0xBC047FB33098286A, 0x153E65AE22E4D2F0, 0xBC3F628AF44DDCEB, 0xCF8C49463A2BEC5D, 0x64D31CBF9A0FAE5B, 0x00000E88DF789F48 },
	{ 0x7E0E3CF3F602CC03, 0x240AE231C56EB636, 0x1630875FADB3CA47, 0x3FDF66239B9021FE, 0x4FA6BEA94AAE8287, 0x20BD32942BAEF1D9, 
	  0x3DBE52BE754CD223, 0xD46D6B986A4C461E, 0x31772CCF6AB0EC49, 0x0362808B445792BE, 0xA57068B23D5D4F04, 0x0000233188CFA1F9 },
	{ 0x5CFEB9EE80FF8802, 0x641C991F35243E77, 0x109BF7F4D15352D9, 0xF57027C40F2AEC39, 0x78834C224A9E8F4D, 0x3B53C38C5DDA4903, 
	  0x2472CAD0E4A1DD20, 0x91121637EFEFBFEB, 0x555DDF1E4E875433, 0xD185E0CEBC9A6BF8, 0x247E7766FEA9846A, 0x00004E24131398C0 },
	{ 0xAE911D5E41FDE1D5, 0x09FD291EAE9A7528, 0xD94DB04CE76D674F, 0xF269A050B317A36A, 0x1010C2464C5B488A, 0x165E22C0571F72CE,
	  0xB649686CDD7FAA40, 0xC65F833CCBC8E854, 0xA1DC607E92B4EC01, 0x6A9F6EA6C5D5598C, 0xB73B45E033D20693, 0x0000126974812437 },
	{ 0x7EF889C1569E078D, 0x8B4790D31AFC6D2F, 0x24BAD80FCF2607D2, 0x13C099586804EDD0, 0x0B219830D09F67F8, 0xFEEBDD0A795A4E0D,
	  0x2C86D567D8A5A5C6, 0x29EFDB5516CD064B, 0xAFB0A05F0230B35C, 0x73FCFA65EC7C5CB4, 0x245E08DC310C14E1, 0x00001778AC2903DF },
	{ 0xF2BF1FF8427C7315, 0x591042D093B90137, 0x23EF8D48782832C9, 0x8DFB39E92296E3D6, 0x0C39FF556BEBDD42, 0x369F6980A4270C5D,
	  0x901F9AD6FCBAA761, 0x0E8E81D435F5FC7F, 0x9A795B9A8409D3D3, 0xD29FB9AE4384290F, 0x3B58F53DD7270C90, 0x00001E27D50D0631 },
	{ 0x838A7C8B0026C13C, 0xD38CAB350DC1F6BD, 0x426C57FE2436E928, 0xB81B289B8792A253, 0xF8EDB68037D3FB8E, 0x677EE0B4C50C01CD, 
	  0xF43DCE6FED67139A, 0xF87EFEBF43D77877, 0x3EEA0E8543763A8A, 0x26E5A18357A35379, 0x55867648B9EA7D35, 0x000069DEC7A3C7DA },
	{ 0x91CCFD3901F3F3FE, 0x2053992393125D73, 0x2129B3A10D7FF7C0, 0x74C64B3E68087A32, 0xEE46C5739B026DF9, 0x53E7B33F97EC0300, 
	  0x14672E57801EC044, 0x18610440AA870975, 0xB6B9D9E0E0097AE6, 0x37AD3B922ED0F367, 0xA737A55936D5A8B8, 0x00005A30AF4F51DA },
	{ 0xC925488939591E52, 0x8F87728BF0ED44E9, 0xF987EF64E4365147, 0x9338B89963265410, 0x340DA16F22024645, 0x5D295419E474BDC1, 
	  0xBA0C2E509FC0510B, 0x957E35D641D5DDB5, 0x922F901AA4A236D8, 0xCBFA24C0F7E172E3, 0xB05A32F88CB5B9DC, 0x00001DC7A766A676 },
	{ 0x6128F8C2B276D2A1, 0x857530A2A633CE28, 0xEB624F41494C5D1E, 0x3FA62AE33B92CCA8, 0x11BCABB4CC4FBE22, 0x91EA14743FDBAC70, 
	  0x9876F7DF900DC277, 0x375FD25E09091CBA, 0x580F3084B099A111, 0x58E9B3FB623FB297, 0x957732F791F6C337, 0x00000B070F784B99 } };