#20211117 Didier Stevens
# mitmproxy script to intercept, decrypt and inject commands into Cobalt Strike beacon network traffic
import base64
import binascii
from math import e
import os
import sys

import Crypto.PublicKey.RSA
import Crypto.Cipher.PKCS1_v1_5
import Crypto.Cipher.AES
import Crypto.Util.Padding

import hashlib
import hmac
import struct
import time
import json
from datetime import datetime

# from kafkaConfig import *

from beaconParse import BeaconPkChangedXORChain
from testKeyChange import  *

# from csparsehttptraffic import  *

CS_FIXED_IV = b'abcdefghijklmnop'

dKeys = {
    "30819f300d06092a864886f70d010101050003818d003081890281810080fa8dc59ec39b73d49523c640c1cdfabbb0f0b15e943f2429c0c360862c938fb474523a0116f2ea71877f24218fc85cd959017cd0f987ec443a731a4d29a7a8fe1312d2edace8a736515d120c8f7b5e0008b7403ee3511435367f223c474ec2c0913c1dede6c1124b5089dc2aec3ef37ce24009a590ef4b8398f52e75c1f2ed02030100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "30820275020100300d06092a864886f70d01010105000482025f3082025b0201000281810080fa8dc59ec39b73d49523c640c1cdfabbb0f0b15e943f2429c0c360862c938fb474523a0116f2ea71877f24218fc85cd959017cd0f987ec443a731a4d29a7a8fe1312d2edace8a736515d120c8f7b5e0008b7403ee3511435367f223c474ec2c0913c1dede6c1124b5089dc2aec3ef37ce24009a590ef4b8398f52e75c1f2ed02030100010281800d789de81f1df515930584b8073976c7126577ae3edfa2fca6f3c0344baf4a363f35cb04cdea54b2d1eac207c70d9a72c02cc0b005af9a57be0490d3156e1d59ac7837c74987a296671f4264781050d39ccc16f5f5024699fe6f3aad9b77e874117e213b369ef6c58c43a4423585db42eb022251914f3110b52532620fe82dad024100f6c00bf6a8e14566029cfdfef39a77c50511056f235a0dc71b46c5d5b17b6494c290496a3d76635d5ae21f615bc5e04e2a2a2001957fec6b3ce88c0ca9a36aaf02410085d04e59788f32150b4039fc0140fa06a66181cb463cdec2d573111e8904fd4aadffa63e8f2f2063c7e212bef5981c1ed2ff6f1163a04662d483067658ceb32302403b44035b9a528935a83906f4be9402626b061c95061bb2257992b51fcf8240b54e4a13a815dd229ea09ea144e42311ee14488be9757c054ff8902e5b383f8cf702407fcd78d74926f2bd58968a0adf23b0e8a30623d2028e666f8d2fae1d0cdec010106947dd1e21f37c794eb97abad4019f8b043d8f4d28a9b100a8f78616c1ac2302403e247b8970b1e457b2c82759d3427a24edfa7d309a4a619ebfcab16cb2593a67564fe7c4d68b73958f856831e9fe1d4ba2ec4281234a2a903b4b07a50084b3d5",
    "30819f300d06092a864886f70d010101050003818d003081890281810084a5630da30447225f084704e282f6bea8bbb0a7043c30d0a85a0ab530d500ab7eb4e76eb6625ff6d65aae874aec7d2e5d2328fec7facabbec4d7d95e90276e6067f35aff4eb50285dcfd9a507a72c7d2e1e759ad171e55cf1b54a65584fd6dff42cd225b75ce08a1eac05b73b8a908e83a5d4784059d41434be80a37909255b02030100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "30820275020100300d06092a864886f70d01010105000482025f3082025b0201000281810084a5630da30447225f084704e282f6bea8bbb0a7043c30d0a85a0ab530d500ab7eb4e76eb6625ff6d65aae874aec7d2e5d2328fec7facabbec4d7d95e90276e6067f35aff4eb50285dcfd9a507a72c7d2e1e759ad171e55cf1b54a65584fd6dff42cd225b75ce08a1eac05b73b8a908e83a5d4784059d41434be80a37909255b02030100010281805ee3fd874cde0b914010a8d58ac10b88fb2641ca4912520d82d1df251d88d310dbf4c837004c41c05039d0eec21f89b1b83925e395e60850054cae11a6fdf755abed6e9075ffecb741a2b08e111b330e4f0531432c7645e1901d203ee48659d5695ceb3491bd060db77909524f6137fc703ffc38bb770b6726990eba5aa89c71024100e0983b76c4750d60e3a6b03e011514eba3a102f32a0d415463e7f96ebc6465d687abe2f13da3494f2b3cb0e56f32100f871320d11fb6885f652e5c72bbf684a30241009731b07dff8a44f22cf4db024016ce65783bb132432075d6dd420d5e7099db11747c25e1fdb04f2786805075d1c3d72bbdd344b88adc3b67eadbc4225bf5afe902403d472bca3ed5d4fd9f7f464cd48cc4f579e29f646b0fccc852ade32f64755c17c9528b8bd88e699d1125f0f9d879e749e547c1c76d08a772a7af9b87ae63175302404dbc07711094679457d6e04f4ce22ce5f0a648197e77cefe54ade42fbd16ed9210e0cf9d5c906c71f6ee3bf0079478298e24743da96f47bfcaf988e2dd82f9190240010485538c262473c0220bdf626974992fc8936be653e02433cd288e87ca0d707ce5feccdded153b9db8933dc2551048611885cb276dfbafe92421df2245664b",
    "30819f300d06092a864886f70d010101050003818d003081890281810093fad989ca301e1c35ea388ed3e0f8d103d7a021ee7dfc75d7084c7bcdf6a799fb4f0f8f008202f7b2c529632bf63572d2dc5029b7857790c5d2006d480100679c29bbfef2a021ad88fb6a0e26d3cd5bd7f6ddd620390cd4748f95ca11b86b641973a1a9b6cde3fa10987911a9ff4a57e4af084f810d40cef98ceb8956e6eb230203010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "30820276020100300d06092a864886f70d0101010500048202603082025c0201000281810093fad989ca301e1c35ea388ed3e0f8d103d7a021ee7dfc75d7084c7bcdf6a799fb4f0f8f008202f7b2c529632bf63572d2dc5029b7857790c5d2006d480100679c29bbfef2a021ad88fb6a0e26d3cd5bd7f6ddd620390cd4748f95ca11b86b641973a1a9b6cde3fa10987911a9ff4a57e4af084f810d40cef98ceb8956e6eb23020301000102818043b630fc5fcc0cbb13e08ce8ae02ef5794ce81b385119907c2d1454e113ca00c517627c463931a108578ba2b6ade4a2eb455a348b3751af4dfcfebea155c7ff633aadced7fb5e0a06d1e1b9bfdd0e619e2eb2913510b195f76f87eea9211b9ca52c6f6ae9fe97e46df01b7c795b69552f684a9e63e08549bdaadbdfc40e0df81024100eb1ecc1f525fc2784e7a7dfe9f247d2a4128afdce4d2234567c95f53cc4572e93eed600fad25e6cf41e718792abcbd25b24c4b901085a0a3db1260cc7e458353024100a11f02a6bb4d1b196243620e03f028baeb69a6a0bd354f6e7882244505dd68728d116d4bda6550b8c795d4c0ace55f644ab39803d629d5e14ca1bcad7d614ef1024069ed681d3c69741deb8d78323cd49da769cfc0db8e23b64c50a402d4a81529de37c18e23c1e86f8234b8bee7e7ff3c603d61ee312ba0686d2a07afa0b1caf38d02401fa036a5039edef2dc96dd6862dd81212f944d60bfc2f7147813138b78db3ce53f4b6c68b735abe2994a8fb84237c3c1abe814aeac1b0a206f2a501ebdbd9c01024100c09a42f14aca7b3ee139f78eaa24b77e173c23ec3aa1a9c2d081c12455f69d1e703ee8c70e834e5545dceb5b5917d2678b102da29873d28e8b16fe6e70cc153b",
    "30819f300d06092a864886f70d010101050003818d0030818902818100a0c19b6be56991586a976ba6f176a4035268fe5d4faf038ccad9becd7f3ab8ab2d78df8e7cb9fc5789d38c8e848b54fdc1ab226059a99dd0a618ed8b776c39856d66ac862edff8e61d5a90cd8b177902f70638ecd085284467fd14cfc086fe073df6cc32b2c9f1b3460183d1e46b85a1d2e7f13bcf4a480a6e2de80b1398b5fd0203010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100a0c19b6be56991586a976ba6f176a4035268fe5d4faf038ccad9becd7f3ab8ab2d78df8e7cb9fc5789d38c8e848b54fdc1ab226059a99dd0a618ed8b776c39856d66ac862edff8e61d5a90cd8b177902f70638ecd085284467fd14cfc086fe073df6cc32b2c9f1b3460183d1e46b85a1d2e7f13bcf4a480a6e2de80b1398b5fd020301000102818100878691942605990e745691e05d834b04adee6c3b989910a21ac5f5f0e3494b34ad12514e9be264561c9127d762f0e0474a860f66315129062571b09a3aa517dc09e2f06d9880e04590ea3aa9dd556778238b64b5512b4f7f6ff752c18f77c24f2002da73a0c15b5d0b2f2a2ad5a3c5538fbe881511dbad711d864a23033e6401024100ce7bf0fe9d175383ebd8a43bda2abacf7f9d0cad5cff56c29447c6ae83094a9b819daf7398d9ee924bc25d8cb503503af8ce739833641d93a73fcf34680c0cfd024100c74e6ebe0c9f4ed0d1d099e77821c71cf9d1eecf707af590bfbfa722248657db2ae3213f77fdb2e060497e86faf9030441eb7440f0e535c2db8f8b77aca41d010240791c69766e5dc8369097397d81b19e7126c0cf36c05d645e2ceb0cb63f55abd51a698b079a97f93f0600b32e5cdddca93a569da6a03e10bb1256730aa21caf610241009a5019e23ff7a09881bb174e666f10b158a3b8591867bb760560a85101229b27703f4760d2d0b50c90c0969c7ff908e2e4ff1e95a16e767f966bbfba3b0b1e01024100b24befa0618f4dd1c6a1ecd3fe2e153276749cef1fb3e13772a9a8bb117e46abb2fa19d707361f81ece7a413648f0032722992a83e909c8a9896458cb3534718",
    "30819f300d06092a864886f70d010101050003818d0030818902818100a2e105c86c51aa20f5acde04b49423b30951600b0741533cd4e31fb0e24cf86b88c4b0e6596663d2425dcfd37dfe743146b06396b2bad828e9461c03cb052b71e5bb7cb17d2afc459007870a5d445ee3dadb5d267a197451e79fd4159347128e9de84da54bb32981042cf637fae69bf71f48046c0f63f49f95cb9af96d7aa61102030100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100a2e105c86c51aa20f5acde04b49423b30951600b0741533cd4e31fb0e24cf86b88c4b0e6596663d2425dcfd37dfe743146b06396b2bad828e9461c03cb052b71e5bb7cb17d2afc459007870a5d445ee3dadb5d267a197451e79fd4159347128e9de84da54bb32981042cf637fae69bf71f48046c0f63f49f95cb9af96d7aa61102030100010281802559ff0e803096182adeb2a75795e53de8741dd74999a471fdcbfbf77f5df1560fae33770fa7585ade574f128c012f3a21a0cfa5be64f4af2517abd2fedab7a46f6d183d2b99400c0cc6edfaf848a0aa47bd7d37d15ad30d09896a1ae66a8a7f36a9c2bad29ff176ea059da23d296edfe1294c88d8c393c62ad1a0a3c3a472b1024100e9b2948230a1788bdaeb0d782694d10a50b1e63b123f696b13ad31b23560386b19cf498d9137ea394534042fd7791706919d27a333c19d18acc2baedb6b42af5024100b26c49989f0ef67e5d6c02705cf34c5293131539d1b8f4c6f6feda86a6dde4d2b48ac71162c75a36889bd84bd9d90065149f67671447f80193c010affb85152d024100a5bb54a083766fb3d71bece07194062f678cd236c039223ca2a6a7e0b703b6df155db0cee9d69a8fe4e8ffb321ff28fa2a9825fd127e5337a5852fe5d7352c6502403e9001ee663794ef124b013fed17d2b751a2eb5a6ed36fe1245290c58e55581b19fb5f7a152cd9d12d6d981660b8da8e97009dfd62fb2957443ba09e548f81b1024006a17a330302d8142084c6c28dce3c6b252af8b8291443d3be98c60ce7d2a2c45ffb5228201875f345b5bd1fc621f90ae63804908afc2b2a503a74ea27a5c5aa",
    "30819f300d06092a864886f70d010101050003818d0030818902818100a70991d69d816a601ffa80976473830f0d3b41276d2790401ddedb18e2d3cab3c315e3222325be42b65adb2878f33f5a03ff5010b23e842a510c1482ad6a42f1e7e5726eb31813e7437640ed7879955f401e172c34d3517241596dd41f8e48d3d1b1c288e6c8752ff65dc27acccba4ba9cd6d0e4de6196cea4da480d3b99d0ed020301000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100a70991d69d816a601ffa80976473830f0d3b41276d2790401ddedb18e2d3cab3c315e3222325be42b65adb2878f33f5a03ff5010b23e842a510c1482ad6a42f1e7e5726eb31813e7437640ed7879955f401e172c34d3517241596dd41f8e48d3d1b1c288e6c8752ff65dc27acccba4ba9cd6d0e4de6196cea4da480d3b99d0ed02030100010281807f61a2dfe1b9619ff0831e31559f6960bf1c62f1682275b50f9275cf229b94c7458c996bdd15d96412a072e50867a7f6437a1e5abd3343a2e9afa6ac8906b2097c61cf5b2bd95418bfc05b2a24405f1a18be182745e9e8669f8c97aa32ef0a13c2245ea7bb3556ea719963ccc01f1e19ec9e90204d5a3466e3b43b094e3d0999024100f56507e3fe143670ddce758e67687958f1747c4e92b7073dfb87d6a3c99634ca1f9e48f28adf26a17f53f931cd949d094f1087d883524435b62ec6aa17ca30db024100ae419e625e48545440bfc30a3ec134a3c961684578a27b265488a9f922a5e1a41c25a506065d3e4a11ed0095933531f4c29c548c64ec374a48e0995220a22bd7024039b361e19832c4825185645af1b1bd26cecfa7130aa882c96e458890c6abcd09e1d96429b3c1b8e1ac80e04d779b8439561ffaf14c1fa1ee47424470665ba295024026250310b166cfdee99590924b8e6b8176f1b5ab8f6eb1da8022b26270ed32e983a7d1e9f1b6b38def429c2021eb41163d0b8f8e740129513f86bac9398f865d024100cd1ce32d491348455d3ecd6462b7ed583d04ce74a8802142d36bb87e8e67ff86fb6d6b5a33ff183d987bf9ad787f5f0b468f74b3d210f10bd0266b504306e47c",
    "30819f300d06092a864886f70d010101050003818d0030818902818100a738cde75f1fbb1c18646c377e03016b162b12ba72bdf7dc36b4cd2e4e9bae12205a95c26170bf908105ad7fa4bbccfa798632261bed9870f975f20794e1fe499523d71f08a56cae0315bfde3d6c8a16386b03b7a6551aa1336d50325a3500db27d78ad8fd13b6a73b9fb7c3fb4d7a088e323f07618656ecd83595fa5f8236130203010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100a738cde75f1fbb1c18646c377e03016b162b12ba72bdf7dc36b4cd2e4e9bae12205a95c26170bf908105ad7fa4bbccfa798632261bed9870f975f20794e1fe499523d71f08a56cae0315bfde3d6c8a16386b03b7a6551aa1336d50325a3500db27d78ad8fd13b6a73b9fb7c3fb4d7a088e323f07618656ecd83595fa5f823613020301000102818059eb70c54ee078341665c1cf61426a7bd412db62491b1ff259b48574b62e7ebf1e88b7692c0e7de44d8ce90bef60514c0b16ff5680c415aa026acaf80ab62f8f30698c7132530ddd46a44b7777387037312e49c59dc5a00e20967435f74cac6703a201ec3431b86008e0d973fa775799bc7b8863037270a33829c081e6cbaa11024100e25d4778e0d1e1e5cb65be3836f5d64af06d054ec6e3b03f78f6bde89ef2d9e4b932b735fc264a5c7a3d2a7c66d00187c3dca51c3ef758fdfde70564c1c2e8e9024100bd1d5576d0e8569d711d5aca42fd808c1f7085c5ced215180360adabd6c553414fdf4ccd9b91d6995c35886636cb14e6f453bff341f56cbae67218c17077099b0240620f127514bf16e29af7da2d33f1cf00eba1ee98afa3d6a7c858eaefa85b7f748b9da2ac2a2cd42db76e63c73c2a835f32c3946ae603f47322d83f07e4bff07102402d2e19e1e5ecebec773ea51717440af6eef7e9eda50889a3900303dabed7ab9939e4c62b84d425a9c3dec2347138b948a7ec6e3a4672c4c42e13ea1824af3bab024100bd154581c5d399c838f476b75482886fcdf194d8419d6564a8dc8b9c074e044359519e3bf6868fc3b4a5f8dd120f5e53813db9fb83fa3ca1fc404ea1c02fe0e5",
    "30819f300d06092a864886f70d010101050003818d0030818902818100a8b144135b042b57a1ca2048f5e0c624b98352933d53ca67003f97e8c3639898674b74a4de9406e05f85678a2ac13b653e7ab4fadf94e771d97ba2ee0dbe5876be50255f00404e094aecbc3ed3b286ac81f9b26a1e26df2c0363d4859e63d4c178d00e3228785f87e48623e64baa0624b88f8c969fd0be4f0e009edc107de50902030100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100a8b144135b042b57a1ca2048f5e0c624b98352933d53ca67003f97e8c3639898674b74a4de9406e05f85678a2ac13b653e7ab4fadf94e771d97ba2ee0dbe5876be50255f00404e094aecbc3ed3b286ac81f9b26a1e26df2c0363d4859e63d4c178d00e3228785f87e48623e64baa0624b88f8c969fd0be4f0e009edc107de50902030100010281806090f9334b4adbb4d27cee7655aa5242fb9f5d49c4358f0bdf6c87fd4abc5cc2017f844a4ccfd80fe11e70e2fb0e9a7d9e8287cf84e5ac87d3c39ec53f40d34a578e4d83754c27cf1dfb128f3f6be73f2a62118a46d0558c9023129196320c27689f1f5d805f622b78ba72aa8777f249c7e9db10301f37d0728cc3672b515931024100e077b061144d5b1ec755d409edfa45fdd313d57da203c3b9c111dc526993efc20f7b33ee7671fadaba6324fb6315184817b6b386dc6b92cd442381a4c94d88fb024100c063ca70c9885ab25b1f91cd5396866d6fdd82e00935109aa4e98c306abfe23423e02a9de14440f47e77188a7ce9cdff2b353f9f5036d9c9b8d9c553907ff2cb024100c4e71938bf8770041ad5e64fe38ae474d9011008c9e345811fa4dc410ace33c666b02b88e62bebe28d17c56c23a97088650ce684c9bc2fa5923d174f872a559b02407835a207291566be2c8ba4396c32105a8edc146b51b573637d09648bd8177f0a5f2430dca7255384b1044f3430ea91c90f415d3879115cb15b2bceccf0ebd153024051dc4bc183d0828850189fb54a62b6f49c1c781cfbe4963356c7703c5825ba322eba5e2e1368b62ab414393d371c8f5df6b8966b621aed933fc469ff4ef3517d",
    "30819f300d06092a864886f70d010101050003818d0030818902818100b22ee1f895f1d872618c1090316c5f5be9488c11056503b8c77fc2969850fe63f6fcd32708e8a5e49095c04526d73a509a46c4351640ce94598a4005d9b0af3b454e0b572002f524f88c34b5d3fbe2ec6508b7dbd6528b340d7fa6bf9a4529635e97845e0329b343b3e6d290665cc3fe852ac135524e7c0a08ab6830a0b0105702030100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "30820277020100300d06092a864886f70d0101010500048202613082025d02010002818100b22ee1f895f1d872618c1090316c5f5be9488c11056503b8c77fc2969850fe63f6fcd32708e8a5e49095c04526d73a509a46c4351640ce94598a4005d9b0af3b454e0b572002f524f88c34b5d3fbe2ec6508b7dbd6528b340d7fa6bf9a4529635e97845e0329b343b3e6d290665cc3fe852ac135524e7c0a08ab6830a0b01057020301000102818100a664f3af21cf9c528c57b16c064b6eedb4f7839dad8cfca1c4e3c142c2f0f7ef404a2fa14747830be41d8454cf85b4366b2be4b4b2984891eee01513a18bc6c6a1c6d21895cc26039f6acbcaa985d2aa08cf5b2155bebf0f4305f960f0d2b123ac6827d932170b7651a26f618ec72b0fd246e9c8ff9528fa95533a3b168b74e9024100e6b53acbc441cbc411b8815c9d959971356e8088477519524e0bf3d77d6d8b71e86d765b72042acb0e590ee1c7ffddaa9c63ed69592e615067c89c72247ac925024100c5b78e39f3553142982f9b730ebc230a641ae2302bc2218e8c82da19e6bdddf0cd756f340c161aa6a11bbbb59ec3fe3aa7cccdf30b5ff9bb2dd6d4919a6b50cb024100e0888b439bab498c768eb26018026c0711308da9949a33ddb595ce68f06ab7e751858f466a8e01b4042fcadb1512418375978f8d133d9f7a68b7870353dba87d024002ec60dcf87d14fa6017ac1bba670bb9969b5326d52ecca237efa35be8ae7bfe987b1906d2faecaff407ddf1a4844f58fcac298b636aaadd9aa2e787b399cc9b02406a5e97f4947b15e3b7feb6160b85228686d0099f3e99938dfd9535b09951b97d35bb6870789ae31f67794be4e2f7919d104e0610346ee7f174580e0da81cf3db"
}

my_pk = "30819f300d06092a864886f70d010101050003818d0030818902818100d8b8f8027c0cb97f9d86763f227b9a48ad75f4728f244730b154195d19687caa0c9bcd14a947ecb80e7cea629f3a2217152b1db64ff9d4cb5a3a42bf4d85338f653ee0e9bcf06f0411957df7bf8e1c30b8852a76bf22ab956eecffecd4391d6777bccd93e2cfae16aa6af477e2776565a8d127cde2906156b66ca0053b770197020301000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
my_sk = "30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100d8b8f8027c0cb97f9d86763f227b9a48ad75f4728f244730b154195d19687caa0c9bcd14a947ecb80e7cea629f3a2217152b1db64ff9d4cb5a3a42bf4d85338f653ee0e9bcf06f0411957df7bf8e1c30b8852a76bf22ab956eecffecd4391d6777bccd93e2cfae16aa6af477e2776565a8d127cde2906156b66ca0053b77019702030100010281807fd7249d3a95bafab76e70e42f3020438ce70eaa611bb24edbdbd31662fd8ac438a9d320c3f6a481b2322784c38e643b9f860e81d3cd78a3f7f674172ae04f17c9a0ceff5e08b186f07737cc50fe20de4bacd891af45cef3ce1874b20ebe23b1a4b1c5d1739960bd103595ea8ff6cd75f28c24f1d470c108bea23b7ac823d4c9024100fdf845108c68a91b1ea48831f4cf43a1bb35fdbb735db2a25ad0926ea9686f07474c1fd9de2ca1129e8d5334990ae4b2ab220d0cca2e55a936c8e798927b1b93024100da7479aa19ad6c0d439c04936d2910538532cdf0d5fe6c681d9279109046b3c47a14a7e787437fee5dc32ae67276efaa6dbbfb25cb222aa8a598d54511d52c6d024058c203a11cf116e89b74f50440828f285ebd27c7f331b3d479d89ad481f0359d5d95852c273181b9781ffc0c4dd038cd1871f60d9a3b4744b418d297c7d9ae71024100b27ecb4e768ea224306311c618429e49702373ec5e1df61c1855af401e72f6be0a76483f40e1a16d76055b4f52a5e5ec5e9f63759d05fccf3207aff330bffafd02400ef5926808d23c3337dc23daec6b512734b2019268ea591553f6c465eba772931f39efdbcedc81c37f21fc4fb1574dfbd8d33afb73ced416147feec524bac1bc"

# cs_pk = "30819f300d06092a864886f70d010101050003818d0030818902818100ad77efa596e0f7b96c136166eb474fbe257711dd5097c06ded2f1f94f5211b2444257c7d363da2f4a2444e78863b49ef01e904106fad8e62d3f5871f431b515c63f151ea1d4c11997898875c3ccbcc766cc2bef341168c2c0252d5b6e74322bcf55fa904f9fba055811059615539e3dd747ab945f89c17ded2983456b66bc4fb0203010001"
# cs_sk = "30820277020100300d06092a864886f70d0101010500048202613082025d02010002818100ad77efa596e0f7b96c136166eb474fbe257711dd5097c06ded2f1f94f5211b2444257c7d363da2f4a2444e78863b49ef01e904106fad8e62d3f5871f431b515c63f151ea1d4c11997898875c3ccbcc766cc2bef341168c2c0252d5b6e74322bcf55fa904f9fba055811059615539e3dd747ab945f89c17ded2983456b66bc4fb02030100010281800dd98c1433fa2d3d2c3055f0022bf4e57117532150ec74cc320a37a2cc7982b1c0112021dd2149afef7eb5a730cc6e083ba64f91426160836a79e97a6900b6dba05fdf06fae00f868716aede4a5aded074927804d80d8b8264f76300a74300d9ae45ab164ae4781c852648cb304ec7fd57e6757f5f126ce3ff24780c83b75219024100db438b7e03602dbf0fafd0e694c3f09a94c300c34ec0758398d1c71519b5c657fefbd48dc986328686e3f08716cea444e8252f6aea155c5428a9cfecbc3db2f3024100ca882e58a245fd828f34fd2851cae3d7918075c9978fb816bd39b9de170de7e51d8fd205708fe5acdd1f2114b447dc717ca9d1194932829283bf381cfb17d7d90241009551d77236ac4e1b1a7cba3ffd39bee616bf020affdb936bce2bb66f4936006036d69b36fff1b300e865dc8cb2dc8104283002adc5c24c4147fbf50c9c594c3f024057ab856c66aa2767e9b7c5523bbdb8cceab611c6b6edc681495e00a02b98a066245aca4e0280b7aa1179d5271236fd2cbf0aff7193a6e2b0ab890db035dd0759024100cc849a5c3a3bf6e65feac2f7c7897728e1b37411e453802c37725ea045821a1c960fae1f8c6573ae1abb908d41d40fcf108cbe70a6d599d8f893f718b0d0f4d7"
# cs_pk = "30819f300d06092a864886f70d010101050003818d0030818902818100ad77efa596e0f7b96c136166eb474fbe257711dd5097c06ded2f1f94f5211b2444257c7d363da2f4a2444e78863b49ef01e904106fad8e62d3f5871f431b515c63f151ea1d4c11997898875c3ccbcc766cc2bef341168c2c0252d5b6e74322bcf55fa904f9fba055811059615539e3dd747ab945f89c17ded2983456b66bc4fb020301000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"


BEACON_COMMAND_SLEEP = 4
BEACON_COMMAND_DATA_JITTER = 6
BEACON_COMMAND_RUN = 78

BEACON_COMMANDS = {
    BEACON_COMMAND_SLEEP:  'SLEEP',
    BEACON_COMMAND_DATA_JITTER:  'DATA_JITTER',
    11: 'DOWNLOAD_START',
    32: 'LIST_PROCESSES',

    3: 'EXIT',
    5: 'CD',
    8: 'CHECKIN',
    11: 'DOWNLOAD',
    12: 'EXECUTE',
    13: 'Tasked beacon to spawn features to default process',
    27: 'GETUID',
    28: 'REVERT_TOKEN',
    33: 'KILL',
    39: 'PWD',
    41: 'JOBS',
    48: 'IP_CONFIG',
    53: 'LIST_FILES',
    54: 'MKDIR',
    55: 'DRIVES',
    56: 'RM',
    72: 'SETENV',
    73: 'CP',
    74: 'MV',
    77: 'GETPRIVS',
    BEACON_COMMAND_RUN: 'RUN',
    80: 'DLLLOAD',
    85: 'ARGUE',
    95: 'GETSYSTEM',
    }

BEACON_OUTPUT = {
    1: 'OUTPUT_KEYSTROKES',
    2: 'DOWNLOAD_START',
    3: 'OUTPUT_SCREENSHOT',
    4: 'SOCKS_DIE',
    5: 'SOCKS_WRITE',
    6: 'SOCKS_RESUME',
    7: 'SOCKS_PORTFWD',
    8: 'DOWNLOAD_WRITE',
    9: 'DOWNLOAD_COMPLETE',
    10: 'BEACON_LINK',
    11: 'DEAD_PIPE',
    12: 'BEACON_CHECKIN', # maybe?
    13: 'BEACON_ERROR',
    14: 'PIPES_REGISTER', # unsure?
    15: 'BEACON_IMPERSONATED',
    16: 'BEACON_GETUID',
    17: 'BEACON_OUTPUT_PS',
    18: 'ERROR_CLOCK_SKEW',
    19: 'BEACON_GETCWD',
    20: 'BEACON_OUTPUT_JOBS',
    21: 'BEACON_OUTPUT_HASHES',
    22: 'TODO', # find out
    23: 'SOCKS_ACCEPT',
    24: 'BEACON_OUTPUT_NET',
    25: 'BEACON_OUTPUT_PORTSCAN',
    26: 'BEACON_EXIT',
    30: 'OUTPUT',
    }


def RSADecrypt(key, data):
    oPrivateKey = Crypto.PublicKey.RSA.importKey(binascii.a2b_hex(key))
    oRSAPrivateKey = Crypto.Cipher.PKCS1_v1_5.new(oPrivateKey)
    ciphertext = data
    try:
        cleartext = oRSAPrivateKey.decrypt(ciphertext, None)
    except ValueError:
        return None
    if cleartext == b'':
        return None   
    return cleartext

"""
实现RSAEncrypt
"""
def RSAEncrypt(key, data):
    # 将十六进制的公钥转换为二进制，并导入为 RSA 公钥对象
    oPublicKey = Crypto.PublicKey.RSA.importKey(binascii.a2b_hex(key))
    oRSAPublicKey = Crypto.Cipher.PKCS1_v1_5.new(oPublicKey)

    # 加密数据
    encrypted_data = oRSAPublicKey.encrypt(data)

    return encrypted_data

class cCrypto(object):

    def __init__(self, rawkey='', hmacaeskeys=''):
        self.rawkey = rawkey
        self.hmacaeskeys = hmacaeskeys
        if self.rawkey != '' and self.rawkey != 'unknown':
            # print(self.rawkey)
            sha256digest = hashlib.sha256(binascii.a2b_hex(self.rawkey)).digest()
            self.hmackey = sha256digest[16:]
            self.aeskey = sha256digest[:16]
        elif self.hmacaeskeys != '' and self.hmacaeskeys != 'unknown':
            self.hmackey = binascii.a2b_hex(self.hmacaeskeys.split(':')[0])
            self.aeskey = binascii.a2b_hex(self.hmacaeskeys.split(':')[1])
        else:
            self.hmackey = None
            self.aeskey = None

    def Decrypt(self, data):
        if self.aeskey == None:
            return data
        encryptedData = data[:-16]
        hmacSignatureMessage = data[-16:]
        hmacsSgnatureCalculated = hmac.new(self.hmackey, encryptedData, hashlib.sha256).digest()[:16]
        # if hmacSignatureMessage != hmacsSgnatureCalculated:
            # raise Exception('HMAC signature invalid')
        cypher = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, CS_FIXED_IV)
        decryptedData = cypher.decrypt(encryptedData)
        return decryptedData

    def Encrypt(self, data):
        cypher = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, CS_FIXED_IV)
        encryptedData = cypher.encrypt(data)
        hmacsSgnatureCalculated = hmac.new(self.hmackey, encryptedData, hashlib.sha256).digest()[:16]
        return encryptedData + hmacsSgnatureCalculated

class cTask(object):
    def __init__(self):
        pass

    @staticmethod
    def PadToMultiple(data, modulo):
        remainder = len(data) % modulo
        if remainder == 0:
            return data
        return data + b'A' * (modulo - remainder)

    @staticmethod
    def Package(taskNumber, arguments=b''):
        command = struct.pack('>II', taskNumber, len(arguments)) + arguments
        data = struct.pack('>II', int(time.time()), len(command)) + command
        return __class__.PadToMultiple(data, 16)

    def Exit(self):
        return __class__.Package(3)

    def Sleep(self, milliseconds, jitter):
        return __class__.Package(4, struct.pack('>II', milliseconds, jitter))


def Unpack(format, data):
    size = struct.calcsize(format)
    result = list(struct.unpack(format, data[:size]))
    result.append(data[size:])
    return result

def StartsWithGetRemainder(strIn, strStart):
    if strIn.startswith(strStart):
        return True, strIn[len(strStart):]
    else:
        return False, None


def GetInstructions(instructions, instructionType):
    for result in instructions.split(';'):
        match, remainder = StartsWithGetRemainder(result, '7:%s,' % instructionType)
        if match:
            if instructionType == 'Output':
                return ','.join(remainder.split(',')[::-1])
            else:
                return remainder
    return ''
def BASE64URLDecode(data):
    paddingLength = 4 - len(data) % 4
    if paddingLength <= 2:
        data += b'=' * paddingLength
    return base64.b64decode(data, b'-_')

def ProcessInstructions(instructions, rawdata, instructionType):
    instructions = GetInstructions(instructions, instructionType)
    if instructions == '':
        instructions = []
    else:
        instructions = [instruction for instruction in instructions.split(',')]
    data = rawdata
    for instruction in instructions:
        instruction = instruction.split(':')
        opcode = int(instruction[0])
        operands = instruction[1:]
        if opcode == 1:
            data = data[:-int(operands[0])]
        elif opcode == 2:
            data = data[int(operands[0]):]
        elif opcode == 3:
            data = binascii.a2b_base64(data)
        elif opcode == 4:
            pass
        elif opcode == 7:
            pass
        elif opcode == 13:
            data = BASE64URLDecode(data)
        elif opcode == 15:
            xorkey = data[0:4]
            ciphertext = data[4:]
            data = []
            for iter, value in enumerate(ciphertext):
                data.append(value ^ xorkey[iter % 4])
            data = bytes(data)
    return data

def FormatTime(epoch=None):
    if epoch == None:
        epoch = time.time()
    return '%04d%02d%02d-%02d%02d%02d' % time.gmtime(epoch)[0:6]


class cStruct(object):
    def __init__(self, data):
        self.data = data
        self.originaldata = data
        self.isFileUpload = False

    def Unpack(self, format):
        formatsize = struct.calcsize(format)
        if len(self.data) < formatsize:
            raise Exception('Not enough data')
        tounpack = self.data[:formatsize]
        self.data = self.data[formatsize:]
        result = struct.unpack(format, tounpack)
        if len(result) == 1:
            return result[0]
        else:
            return result

    def Truncate(self, length):
        self.data = self.data[:length]

    def GetBytes(self, length=None):
        if length == None:
            length = len(self.data)
        result = self.data[:length]
        self.data = self.data[length:]
        return result

    # 首先获取data长度，然后获取字符串
    def GetString(self, format):
        stringLength = self.Unpack(format)
        return self.GetBytes(stringLength)

    def Length(self):
        return len(self.data)
def ProcessReplyPacketDataMITM(hexdata, oOutput, oCrypto, dCommandsSummary,):
    rawdata = binascii.a2b_hex(hexdata)
    oOutput.Line('Length raw data: %s' % len(rawdata))
    rawdata = ProcessInstructions('', rawdata, 'Input')
    if rawdata == b'':
        oOutput.Line('No data')
        oOutput.Line('')
        return
    try:
        data = oCrypto.Decrypt(rawdata)
    except Exception as e:
        if e.args != ('HMAC signature invalid',):
            raise
        oOutput.Line('HMAC signature invalid')
        return
    if data == b'':
        oOutput.Line('No data')
    elif data.startswith(b'MZ'):
        oOutput.Line('MZ payload detected')
        oOutput.Line(' MD5: ' + hashlib.md5(data).hexdigest())
        # ExtractPayload(data, options)
    else:
        timestamp, datasize, data = Unpack('>II', data)
        oOutput.Line('Timestamp: %d %s' % (timestamp, FormatTime(timestamp)))
        oOutput.Line('Data size: %d' % datasize)
        data = data[:datasize]
        while len(data) > 0:
            command, argslen, data =  Unpack('>II', data)
            dCommandsSummary[command] = dCommandsSummary.get(command, 0) + 1
            oOutput.Line('Command: %d %s' % (command, BEACON_COMMANDS.get(command, 'UNKNOWN')))
            if command == BEACON_COMMAND_SLEEP:
                sleep, jitter, _ = Unpack('>II', data)
                oOutput.Line(' Sleep: %d' % sleep)
                oOutput.Line(' Jitter: %d' % jitter)
            elif command == BEACON_COMMAND_DATA_JITTER:
                oOutput.Line(' Length random data = %d' % argslen)
            elif command == BEACON_COMMAND_RUN:
                payload = data[:argslen]
                oStruct = cStruct(payload)
                oOutput.Line(' Command: %s' % oStruct.GetString('>I'))
                oOutput.Line(' Arguments: %s' % oStruct.GetString('>I'))
                oOutput.Line(' Integer: %d' % oStruct.Unpack('>H'))
            else:
                oOutput.Line(' Arguments length: %d' % argslen)
                if argslen > 0:
                    if command in [40, 62]:
                        payload = data[:argslen]
                        oStruct = cStruct(payload)
                        oOutput.Line(' Unknown1: %d' % oStruct.Unpack('>I'))
                        oOutput.Line(' Unknown2: %d' % oStruct.Unpack('>I'))
                        oOutput.Line(' Pipename: %s' % oStruct.GetString('>I'))
                        oOutput.Line(' Command: %s' % oStruct.GetString('>I'))
                        oOutput.Line(' ' + repr(oStruct.GetBytes()))
                    else:
                        oOutput.Line(' ' + repr(data[:argslen])[:100])
                        payload = data[:argslen]
                        oOutput.Line(' MD5: ' + hashlib.md5(payload).hexdigest())
                        # ExtractPayload(payload, options)
            data = data[argslen:]

    oOutput.Line('')

def ExtractPayload(data):
    current_time = time.strftime('%Y%m%d%H%M%S')  # 格式化当前时间为 'YYYYMMDDHHMMSS'
    file_path = 'files/payload-%s-%s.vir' % (hashlib.md5(data).hexdigest(), current_time)
    with open(file_path, 'wb') as fWrite:
        fWrite.write(data)

def ProcessPostPacketDataSub(data, oOutput, oCrypto, dCallbacksSummary):
    isFileUpload = False
    oStructData = cStruct(oCrypto.Decrypt(data))
    # print("cs-mitm:POST 上传数据内容： ", oStructData.data)
    # 提取前 4 个字节，并将其解释为一个大端字节序的无符号整数，代表计数counter
    counter = oStructData.Unpack('>I')
    oOutput.Line('Counter: %d' % counter)
    # 之后 4 个字节是数据长度
    oStructCallbackdata = cStruct(oStructData.GetString('>I'))
    callback = oStructCallbackdata.Unpack('>I')
    callbackdata = oStructCallbackdata.GetBytes()
    oStructCallbackdataToParse = cStruct(callbackdata)
    oOutput.Line('Callback: %d %s' % (callback, BEACON_OUTPUT.get(callback, 'UNKNOWN')))
    dCallbacksSummary[callback] = dCallbacksSummary.get(callback, 0) + 1
    if callback in [0, 25]:
        oOutput.Line('-' * 100)
        oOutput.Line(callbackdata.decode())
        oOutput.Line('-' * 100)
    elif callback == 22:
        oOutput.Line(repr(callbackdata[:4]))
        oOutput.Line('-' * 100)
        oOutput.Line(callbackdata[4:].decode('latin'))
        oOutput.Line('-' * 100)
    elif callback == 2:
        isFileUpload = True
        parameter1, length = oStructCallbackdataToParse.Unpack('>II')
        filenameDownload = oStructCallbackdataToParse.GetBytes()
        oOutput.Line(' parameter1: %d' % parameter1)
        oOutput.Line(' length: %d' % length)
        oOutput.Line(' filenameDownload: %s' % filenameDownload.decode())
    elif callback in [17, 30, 32]:
        oOutput.Line(callbackdata.decode())
    elif callback in [3, 8]:
        oOutput.Line(' Length: %d' % len(callbackdata[4:]))
        oOutput.Line(' MD5: ' + hashlib.md5(callbackdata[4:]).hexdigest())
        ExtractPayload(callbackdata[4:])
    else:
        oOutput.Line(repr(callbackdata))
    extradata = oStructData.GetBytes()[:-16] # drop hmac
    if len(extradata) > 0:
        oOutput.Line('Extra packet data: %s' % repr(extradata))

    oOutput.Line('')
    return isFileUpload



def ProcessPostPacketDataMITM(hexdata, oOutput, oCrypto, dCallbacksSummary):
    rawdata = binascii.a2b_hex(hexdata)
    oOutput.Line('Length raw data: %s' % len(rawdata))
    rawdata = ProcessInstructions('', rawdata, 'Output')

    if rawdata == b'':
        oOutput.Line('No data')
        oOutput.Line('')
        return False
    # if options.rawkey == 'unknown' or options.hmacaeskeys == 'unknown':
    #     oOutput.Line(binascii.b2a_hex(rawdata).decode())
    #     oOutput.Line('')
    #     return
    isFileUpload = False
    oStructData = cStruct(rawdata)
    while oStructData.Length() > 0:
        isFileUpload = ProcessPostPacketDataSub(oStructData.GetString('>I'), oOutput, oCrypto, dCallbacksSummary) or isFileUpload

    return isFileUpload

def modifyPostPacketData(hexdata, oCrypto, filename):
    """
        替换data内容 , 分为三部分，第一部分是下载开始，第二部分是下载写入，第三部分是下载完成，每一部分都要解密-修改-加密
            第一部分 解密-定位数据长度字段，修改-加密
            第二部分 解密-修改为要替换的文件-加密
            第三部分 不变
        拼接返回？
    """
    rawdata = binascii.a2b_hex(hexdata)
    block_size = 16
    def pad_with_zero(data, block_size):
        # 计算需要填充的字节数
        padding_length = (block_size - len(data) % block_size) % block_size
        # 使用\x00进行填充
        return data + b'\x00' * padding_length
    
    oStructData = cStruct(rawdata)
    with open(filename, 'rb') as myFile:
        fileContent = myFile.read()
        fileLength = len(fileContent)
        fileLengthBytes = struct.pack('>I', fileLength)

        # 第一部分：downloadStart
        startDataLength = oStructData.data[:4]
        startData = oStructData.GetString('>I')
        startData = cStruct(oCrypto.Decrypt(startData))
        print("cs-mitm: 替换downloadStart前:",startData.data)
        # counter(4) - length(4) - callback(4) - parameter1(4) - length(4) - filepath(...)
        startDataNew = startData.data[:16] + fileLengthBytes + startData.data[20:]
        print("cs-mitm: 替换downloadStart后:",startDataNew)

        startDataNew = startDataLength + oCrypto.Encrypt(startDataNew)

        # 第二部分：downloadWrite
        # length(4) -  counter(4) - length(4) - callback(4) - filepath(...)
        writeData = oStructData.GetString('>I')
        writeData = oCrypto.Decrypt(writeData)
        print("cs-mitm: 替换downloadWrite前:",writeData)
        writeData = (
            writeData[:4] + # counter
            struct.pack('>I', fileLength + 8) + # length
            writeData[8:12] + # callback
            writeData[12:16] + # 文件长度?好像不是
            fileContent # 文件内容
        )
        print("cs-mitm: 替换downloadWrite后,padding前:",writeData)
        writeData = pad_with_zero(writeData, block_size)
        print("cs-mitm: 替换downloadWrite后,padding后:",writeData)
        writeDataNew = oCrypto.Encrypt(writeData)
        writeDataNew = struct.pack('>I', len(writeDataNew)) + writeDataNew

        # 第三部分：downloadEnd
        endData = oStructData.data

        # 拼接
        dataNew = startDataNew + writeDataNew + endData
        return dataNew

class cOutput():
    def __init__(self, filenameOption=None, log_to_string=False):
        self.starttime = time.time()
        self.filenameOption = filenameOption
        self.separateFiles = False
        self.progress = False
        self.console = False
        self.fOut = None
        self.rootFilenames = {}

        self.log_to_string = log_to_string  # 新增的标志，控制是否记录到字符串
        self.log_string = ""  # 用于存储记录的输出内容

        if self.filenameOption:
            if self.ParseHash(self.filenameOption):
                if not self.separateFiles and self.filename != '':
                    self.fOut = open(self.filename, 'w')
            elif self.filenameOption != '':
                self.fOut = open(self.filenameOption, 'w')
        self.dReplacements = {}

    def Replace(self, line):
        for key, value in self.dReplacements.items():
            line = line.replace(key, value)
        return line

    def ParseHash(self, option):
        if option.startswith('#'):
            position = self.filenameOption.find('#', 1)
            if position > 1:
                switches = self.filenameOption[1:position]
                self.filename = self.filenameOption[position + 1:]
                for switch in switches:
                    if switch == 's':
                        self.separateFiles = True
                    elif switch == 'p':
                        self.progress = True
                    elif switch == 'c':
                        self.console = True
                    elif switch == 'l':
                        pass
                    elif switch == 'g':
                        if self.filename != '':
                            extra = self.filename + '-'
                        else:
                            extra = ''
                        self.filename = '%s-%s%s.txt' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], extra, self.FormatTime())
                    else:
                        return False
                return True
        return False

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def RootUnique(self, root):
        if not root in self.rootFilenames:
            self.rootFilenames[root] = None
            return root
        iter = 1
        while True:
            newroot = '%s_%04d' % (root, iter)
            if not newroot in self.rootFilenames:
                self.rootFilenames[newroot] = None
                return newroot
            iter += 1

    def Line(self, line, eol='\n'):
        line = self.Replace(line)
        if self.log_to_string:
            # 如果开启了记录到字符串功能，则将输出追加到 log_string 中
            self.log_string += line + eol
        else:
            if self.fOut == None or self.console:
                try:
                    print(line, end=eol)
                except UnicodeEncodeError:
                    encoding = sys.stdout.encoding
                    print(line.encode(encoding, errors='backslashreplace').decode(encoding), end=eol)
    #            sys.stdout.flush()
            if self.fOut != None:
                self.fOut.write(line + '\n')
                self.fOut.flush()

    def LineTimestamped(self, line):
        self.Line('%s: %s' % (self.FormatTime(), line))

    def Filename(self, filename, index, total):
        self.separateFilename = filename
        if self.progress:
            if index == 0:
                eta = ''
            else:
                seconds = int(float((time.time() - self.starttime) / float(index)) * float(total - index))
                eta = 'estimation %d seconds left, finished %s ' % (seconds, self.FormatTime(time.time() + seconds))
            # PrintError('%d/%d %s%s' % (index + 1, total, eta, self.separateFilename))
        # if self.separateFiles and self.filename != '':
        #     oFilenameVariables = cVariables()
        #     oFilenameVariables.SetVariable('f', self.separateFilename)
        #     basename = os.path.basename(self.separateFilename)
        #     oFilenameVariables.SetVariable('b', basename)
        #     oFilenameVariables.SetVariable('d', os.path.dirname(self.separateFilename))
        #     root, extension = os.path.splitext(basename)
        #     oFilenameVariables.SetVariable('r', root)
        #     oFilenameVariables.SetVariable('ru', self.RootUnique(root))
        #     oFilenameVariables.SetVariable('e', extension)
        #
        #     self.Close()
        #     self.fOut = open(oFilenameVariables.Instantiate(self.filename), 'w')

    def Close(self):
        if self.fOut != None:
            self.fOut.close()
            self.fOut = None

class BeaconKey:
    def __init__(self, aesKey, publicKey):
        self.aesKey = aesKey
        self.publicKey = publicKey

    def __str__(self):
        return f"BeaconKey(aesKey={self.aesKey}, publicKey={self.publicKey})"
    
# 读取文件到dict的代码:
def load_beacon_keys():
    try:
        dict_beacon_key = {}
        with open('beacon_keys.txt', 'r') as f:
            for line in f:
                ip, pubkey, aeskey = line.strip().split(',')
                dict_beacon_key[ip] = BeaconKey(aeskey, pubkey)
        return dict_beacon_key
    except FileNotFoundError:
        return {}
    
def checksum(var0: str) -> int:
    if len(var0) < 4:
        return 0

    var0 = var0.replace("/", "")
    var1 = 0

    for char in var0:
        var1 += ord(char)

    return var1 % 256


def is_stager_url(uri: str) -> bool:
    # print(checksum(uri))
    return checksum(uri) == 92 or checksum(uri) == 93

def get_key_from_flow(flow):
    key = flow.client_conn.address[0]+"-"+flow.server_conn.address[0] #+"-" + str(flow.server_conn.address[1]) 
    return key


dRawkeys = {}
rawkeyHex = ""
# oOutput = cOutput("save_file")
dCommandsSummary = {}
cs_pk = b""
dict_beacon_key = load_beacon_keys()
beacon_key_file = "beacon_keys.txt"


class Addon:


    def __init__(self):
        self.exporter = None
        global dict_beacon_key
        if dict_beacon_key is None:
            dict_beacon_key = {} 
        for key, value in dict_beacon_key.items():
            print(f"{key}: {value}")
        print("cs-mitm: 读取beacon_keys.txt文件成功")

    from mitmproxy import http

    def request(self, flow) -> None:

        if flow.request.method == 'GET': # 阶段一、阶段二
            if 'Cookie' in flow.request.headers: # 阶段二，获取metadata
                key = get_key_from_flow(flow)
                # print(key)
                # print(dict_beacon_key)
                beaconKey = dict_beacon_key.get(get_key_from_flow(flow))
                # print(beaconKey)
                #获取原始cookie
                original_cookie = flow.request.headers.get('Cookie')
                print(original_cookie)
                # original_cookie = original_cookie.lstrip("auth_tokenZK4D=")
                encryptedMetadata = binascii.a2b_base64(original_cookie)

                # 解密原始 Cookie，使用自己的私钥
                decryptedMetadata = RSADecrypt(my_sk, encryptedMetadata)
                if decryptedMetadata != None:
                    if beaconKey !=None and beaconKey.aesKey != None:
                        print("cs-mitm: 拦截到beacon心跳包")
                        print('cs-mitm: 已经记录该beacon公钥')
                    else:
                        print("cs-mitm: 拦截到beacon心跳包,且未记录")
                        print('cs-mitm: 记录该beacon公钥至dict')
                        print(decryptedMetadata)
                        # 获取aes-key
                        rawkey = decryptedMetadata[8:8 + 16]
                        # rawkeyHex = binascii.b2a_hex(rawkey)
                        beaconKey.aesKey = rawkey.hex() 
                        print('cs-mitm: 记录至'+beacon_key_file + str(beaconKey))
                        # 把beacon ip: 公钥: aes密钥写入文件暂存,格式: ip,publicKey,aesKey
                        with open(beacon_key_file, 'a') as f:
                            key = get_key_from_flow(flow)
                            f.write(f"{key},{beaconKey.publicKey},{beaconKey.aesKey}\n")
                        

                        data = {
                            "victim_ip": flow.client_conn.address[0].split(":")[-1],
                            "c2_ip": flow.server_conn.address[0],
                            "victim_port": str(flow.client_conn.address[1]) ,
                            "c2_port": str(flow.server_conn.address[1]) ,
                            "http_url": flow.request.host + flow.request.path,
                            "Type": 1,
                            "message": f"上线心跳包： 首次拦截本次木马上线心跳包,获取到通信AES密钥:{beaconKey.aesKey}",
                            "c2_pk": beaconKey.publicKey,
                            "send_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }

                        # 数据字段
                        # data = {
                        #     "victim_ip": "1.2.3.4",
                        #     "c2_ip": "2.3.4.5",
                        #     "victim_port": "33333",
                        #     "c2_port": "8080",
                        #     "http_url": "2.3.4.5:8080/submit.php",
                        #     "Type": 1,
                        #     "message": "回传数据：\nC:\\Users\\lee\\Desktop\\cs-beacon\\mitm-test\\*\nD 0 02/23/2025 02:56:36 .\nD 0 02/23/2025 02:56:36 ..\nF 19456 02/23/2025 02:56:22 malware.exe",
                        #     "c2_pk": "30819f300d06092a864886f70d010101050003818d003081890281810080fa8dc59ec39b73d49523c640c1cdfabbb0f0b15e943f2429c0c360862c938fb474523a0116f2ea71877f24218fc85cd959017cd0f987ec443a731a4d29a7a8fe1312d2edace8a736515d120c8f7b5e0008b7403ee3511435367f223c474ec2c0913c1dede6c1124b5089dc2aec3ef37ce24009a590ef4b8398f52e75c1f2ed02030100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        #     "send_time": "2025-04-11 15:12:13",
                        #     "association_id": "18909889-f4b4-42d4-9bf6-54cc387f9dff",
                        #     "task_id": 11111
                        # }

                        # 将数据转为JSON格式
                        json_data = json.dumps(data, ensure_ascii=False, indent=4)
                        print(json_data)
                        



                        
                    cs_publicKey = beaconKey.publicKey
                    # 将cookie重新用原始公钥加密
                    encrypted_cookie_by_cs_pk = binascii.b2a_base64(RSAEncrypt(cs_publicKey.rstrip('0'), decryptedMetadata))
                    # 设置回请求头中
                    flow.request.headers['Cookie'] = encrypted_cookie_by_cs_pk

        if flow.request.method == 'POST': # 阶段三
        # 这是beacon上传的任务执行结果数据
            # 解密beacon的请求
            if flow.request.content != b'':
                print('拦截到beacon上传数据')
                beaconKey = dict_beacon_key.get(get_key_from_flow(flow))
                aesKey = beaconKey.aesKey
                oCrypto = cCrypto(rawkey=aesKey)
                # request_data_decrypt = oCrypto.Decrypt(flow.request.content).decode('utf-8')

                # print(f'解密beacon发送的数据: {request_data_decrypt}')
                oOutput = cOutput(filenameOption="save_file", log_to_string=True) 

                isFileUpload = ProcessPostPacketDataMITM(binascii.b2a_hex(flow.request.content), oOutput, oCrypto, {})
                # 判断是否为文件上传
                if isFileUpload:
                    # return
                    myFilePath = 'files/myfile.txt'
                    print('cs-mitm: 拦截到beacon上传文件,替换为',myFilePath)
                    PostPacketData = modifyPostPacketData(binascii.b2a_hex(flow.request.content), oCrypto, myFilePath)
                    flow.request.set_content(PostPacketData)

                    ProcessPostPacketDataMITM(binascii.b2a_hex(flow.request.content), oOutput, oCrypto, {})
                data = {
                        "victim_ip": flow.client_conn.address[0].split(":")[-1],
                        "c2_ip": flow.server_conn.address[0],
                        "victim_port": str(flow.server_conn.address[1]) ,
                        "c2_port": str(flow.server_conn.address[1]) ,
                        "http_url": flow.request.host + flow.request.path,
                        "Type": 1,
                        "message": f"数据上传：{oOutput.log_string}",
                        "c2_pk": beaconKey.publicKey,
                        "send_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    # 将数据转为JSON格式
                json_data = json.dumps(data, ensure_ascii=False, indent=4)
                print(json_data)
                    
    # def request(self, flow):
    #     return
            
    # def response(self, flow):
    #     return

    def response(self, flow):
        # 这是C2的响应，针对GET的响应，数据是beacon要执行的任务   
        if flow.request.method =='GET':   #阶段一、阶段二
            print('cs-mitm: 拦截到GET请求',flow.request.path)
            if not flow.request.path.startswith('/j.ad') and (is_stager_url(flow.request.path) or flow.request.path.startswith('/Level') or flow.request.path.startswith('/ab') or flow.request.path.startswith('/a')): # 阶段一 or 之前没有记录过ip四元组
                if flow.response.raw_content != b'':
                    ori_response = flow.response.raw_content
                    # stager payload 还是 scripted web delivery 
                    if ori_response.startswith(b'$s=New-Object IO.MemoryStream'): #scripted web delivery 
                        # print("cs-mitm: 进行公钥替换ing")
                        original_pub_key_xor, new_beacon = change_to_new_pubKey(ori_response)
                        # global cs_pk
                        cs_pk = original_pub_key_xor.hex()

                        dict_beacon_key[get_key_from_flow(flow)] = BeaconKey(aesKey=None, publicKey=cs_pk)
                        beaconKey = dict_beacon_key.get(get_key_from_flow(flow))

                        print("cs-mitm: ----拦截到beacon下载,进行公钥修改----")
                        print("cs-mitm: 原始公钥为--",end='')
                        print(cs_pk)
                        #flow.response.raw_content = new_beacon
                        flow.response.set_content(new_beacon)
                        data = {
                            "victim_ip": flow.client_conn.address[0].split(":")[-1],
                            "c2_ip": flow.server_conn.address[0],
                            "victim_port": str(flow.server_conn.address[1]) ,
                            "c2_port": str(flow.server_conn.address[1]) ,
                            "http_url": flow.request.host + flow.request.path,
                            "Type": 0,
                            "message": f"Beacon下载：拦截到beacon下载,进行公钥修改,原始公钥为{cs_pk}，替换为{my_pk}，下载beacon长度为{len(new_beacon)}",
                            "c2_pk": beaconKey.publicKey,
                            "send_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }

                        # 将数据转为JSON格式
                        json_data = json.dumps(data, ensure_ascii=False, indent=4)
                        print(json_data)


                    else: #  stager payload
                        ori_response = flow.response.raw_content
                        print('cs-mitm: 拦截到stager下载行为')

                        dataPkChanged, csPubKey = BeaconPkChangedXORChain(ori_response)

                        csPubKey = csPubKey.hex()
                    
                        print('cs-mitm: stager payload 下载pk已替换')
                        print(dataPkChanged[:100])
                        # TODO: dict的key重新设计
                        dict_beacon_key[get_key_from_flow(flow)] = BeaconKey(aesKey=None, publicKey=csPubKey)
                        flow.response.set_content(dataPkChanged)
                        beaconKey = dict_beacon_key.get(get_key_from_flow(flow))


                        data = {
                            "victim_ip": flow.client_conn.address[0].split(":")[-1],
                            "c2_ip": flow.server_conn.address[0],
                            "victim_port": str(flow.server_conn.address[1]) ,
                            "c2_port": str(flow.server_conn.address[1]) ,
                            "http_url": flow.request.host + flow.request.path,
                            "Type": 0,
                            "message": f"Beacon下载：拦截到beacon下载,进行公钥修改,原始公钥为{cs_pk}，替换为{my_pk}，下载beacon长度为{len(new_beacon)}",
                            "c2_pk": beaconKey.publicKey,
                            "send_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }

                        # 将数据转为JSON格式
                        json_data = json.dumps(data, ensure_ascii=False, indent=4)
                        
                        print(json_data)

            else: # 阶段二 命令控制-任务
                if flow.response.raw_content != b'':
                    ori_response = flow.response.raw_content
                    print(f'cs-mitm: 收到listener -> beacon 的控制指令(未解密): {ori_response}')
                    beaconKey = dict_beacon_key.get(get_key_from_flow(flow))
                    rawAESKey = beaconKey.aesKey
                    oCrypto = cCrypto(rawkey=rawAESKey)
                    decryptedData = oCrypto.Decrypt(flow.response.raw_content)
                    print(f'cs-mitm: 收到listener -> beacon 的控制指令(已解密): {decryptedData}')
                    # global  oOutput
                    oOutput = cOutput(filenameOption="save_file", log_to_string=True) 
                    ProcessReplyPacketDataMITM(binascii.b2a_hex(ori_response), oOutput, oCrypto, dCommandsSummary)
                    print(f'cs-mitm: 收到listener -> beacon 的控制指令(已解析): {oOutput.log_string}')
                    data = {
                            "victim_ip": flow.client_conn.address[0].split(":")[-1],
                            "c2_ip": flow.server_conn.address[0],
                            "victim_port": str(flow.server_conn.address[1]) ,
                            "c2_port": str(flow.server_conn.address[1]) ,
                            "http_url": flow.request.host + flow.request.path,
                            "Type": 0,
                            "message": f"控制指令下发：{oOutput.log_string}",
                            "c2_pk": beaconKey.publicKey,
                            "send_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }

                        # 将数据转为JSON格式
                    json_data = json.dumps(data, ensure_ascii=False, indent=4)

                    print(json_data)

        if flow.request.method =='POST': # 阶段三
            pass  


            


"""
            for publicKey, privateKey in dKeys.items():
                if decryptedMetadata != None:
                    print('cs-mitm: %s' % 'Found and decrypted metadata')
                    rawkey = decryptedMetadata[8:8 + 16]
                    rawkeyHex = binascii.b2a_hex(rawkey)
                    print('cs-mitm: %s' % ('Raw key: %s' % rawkeyHex))
                    dRawkeys[rawkey] = dRawkeys.get(rawkey, 0) + 1
                    oCrypto = cCrypto(rawkey=rawkeyHex)
                    if dRawkeys[rawkey] == 1:
                        exitTask = oCrypto.Encrypt(cTask().Sleep(5000, 0)) # sleep 5 seconds
                        print('cs-mitm: %s' % 'Sending "sleep 5" command')
                    elif dRawkeys[rawkey] == 2:
                        exitTask = oCrypto.Encrypt(cTask().Exit()) # exit
                        print('cs-mitm: %s' % 'Sending "exit" command')
                    print('cs-mitm: %s' % flow.response.headers)
                    print('cs-mitm: %s' % flow.response.raw_content)
                    flow.response.headers['Content-Length'] = b'%d' % len(exitTask)
                    flow.response.raw_content = exitTask
                    print('cs-mitm: %s' % flow.response.headers)
                    print('cs-mitm: %s' % flow.response.raw_content)
                    break
"""

        # if flow.request.path == '/adfd':
        #     if flow.response.raw_content

addons = [Addon()]



if __name__ == '__main__':

        from mitmproxy.tools.main import mitmdump,mitmproxy 
        import sys
        import traceback
        sys.argv = [
            __file__,  # 必须包含
            "-s", __file__, # 加载脚本文件
            # "--mode", "upstream:http://127.0.0.1:7890",
            # "--no-http2"
            "--mode", "transparent",
            # "--set", "spoof_source_address",
            # "--listen-host", "0.0.0.0",
            # "--listen-port","8999",
            "--ssl-insecure",
            "--set", "termlog_verbosity=debug" # 开启debug，可以输出更多的保存信息
            # "-q"
        ]
        try:
            sys.exit(mitmdump())
        except:
            traceback.print_exc()  # 打印堆栈跟踪信息
            sys.exit(1)

"""
sudo -u mitmproxy ./mitmproxy_shim /home/push/Desktop/cs-mitm/venv/bin/mitmdump  --mode transparent --set spoof_source_address --listen-host 0.0.0.0 --listen-port 8999 --ssl-insecure --set termlog_verbosity=debug -s cs-mitm.py 

"""