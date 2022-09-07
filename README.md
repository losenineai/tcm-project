# 1 可信标准
可信技术标准有国际标准TPM和中国大陆标准TCM。
## 1.1 TPM
可信平台模块TPM（Trusted Platform Module）是一项安全密码处理器（Secure cryptoprocessor）的 ***国际标准***，旨在使用设备中集成的专用微控制器（安全硬件）处理设备中的加密密钥。TPM的技术规范（Specification Technical standard）由[可信计算组织TCG（Trusted Computing Group）](https://trustedcomputinggroup.org/)的相关产业联合体编写。

国际标准化组织（ISO）和国际电工委员会（IEC）已于2009年将规范标准化为[ISO/IEC 11889-1:2009](https://www.iso.org/standard/50970.html)和2015年的更新版本[ISO/IEC 11889-1:2015](https://www.iso.org/standard/66510.html)。
## 1.2 TCM
为自主可控，不受制于人，中国大陆按照密码算法 ***自主研制的具有完全自主知识产权*** 的可信计算标准产品。TCM（Trusted Cryptography Module）由长城、中兴、联想、同方、方正、兆日等十二家厂商联合推出，得到国家密码管理局的大力支持，TCM安全芯片在系统平台中的作用是为系统平台和软件提供基础的安全服务，建立更为安全可靠的系统平台环境。

中国大陆制造TPCM芯片的公司有[国民技术](https://www.nationstech.com/)，[可信华泰](https://www.httc.com.cn/)等。
# 2 各部件功能
## TPCM模块
TPCM（Trusted Platform Control Module）为可信平台控制模块；让可信平台模块具有对平台资源进行控制的功能。
### I/O部件
完成总线协议的编码和译码，并实现TPM与外部的信息交换
### 密码协处理器
用来实现加密、解密、签名和验证签名的硬件加速
### HMAC引擎
实现基于SHA-1的Hash函数消息认证码HMAC的硬件引擎，其计算根据RFC2014规范
### SHA-1引擎
Hash函数SHA-1的硬件执行
### 密钥生成部件
用于产生RSA密钥对
### 随机数发生器
TPM内置的随机源，用于产生随机数
### 电源检测部件
管理TPM的电源状态
### 执行引擎
包含CPU和相应的嵌入式软件，通过软件的执行来完成TPM的任务
### 非易失性存储器（NVM）
用于存储嵌入式操作系统及其文件系统，存储密钥、证书、标识等重要数据，读写属性是可以单独控制的，这也就意味着用户不需要担心因为意外或者恶意攻击造成数据被擦除（不可写）
### 平台状态寄存器（PCR）
PCR为易失存储，用来记录系统运行状态的寄存器，TPM只允许两种操作来修改PCR的值：重置操作（Reset）和扩展操作（Extend），重置操作发生在机器断电或者重新启动之后，PCR的值自动重新清零。
# 3 编译及测试
## 3.1 编译
```
sudo make clean
sudo make
```
## 3.2 测试
### 3.2.1 启动TPCM设备
```
# ./tcm_test /s /dd

FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

input data:
00000000 | 00 c1 00 00 00 0c 00 00   80 99 00 01

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 26

TCM_Startup Success
```
### 3.2.2 激活TPCM设备
```
# ./tcm_test /sa /dd

FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

input data:
00000000 | 00 c1 00 00 00 0b 00 00   80 72 00

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

TCM_PhysicalSetActivated(0) Success
```
### 3.2.3 恢复出厂状态
```
# ./tcm_test /f /dd

FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

input data:
00000000 | 00 c1 00 00 00 0a 00 00   80 5d

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

TCM_ForceClear Success
```
### 3.2.4 创建授权信息
```
# ./tcm_test /np 1234567890abcdef1234567890abcdef /dd

FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

new auth
b:  输入passwd先转成如下16进制格式
00000000 | 12 34 56 78 90 ab cd ef 12 34 56 78 90 ab cd ef  | .4Vx⚌⚌⚌⚌.4Vx⚌⚌⚌⚌

hash:   输入passwd的hash值
00000000 | 27 1f b6 70 63 53 dc 06 0a be ce a9 54 8e 7a 47  | '.⚌pcS⚌..⚌ΩT⚌zG
00000010 | 84 32 3f 12 68 e9 fd 7d e5 1c 05 de 2d 05 16 7d  | ⚌2?.h⚌⚌}⚌..⚌-..}

input data:  read pub ek
00000000 | 00 c1 00 00 00 2a 00 00   80 7c 00 00 00 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00

output data:
00000000 | 00 c4 00 00 00 7f 00 00   00 00 00 00 00 0b 00 06
00000010 | 00 01 00 00 00 04 00 00   01 00 00 00 00 41 04 cf
00000020 | dc c8 5e e5 50 47 ab f3   f1 f0 03 ab 44 62 84 c7
00000030 | e6 14 56 86 ee c5 7b ce   f3 ba 62 5f 47 52 1f 05
00000040 | 05 8f 21 45 25 68 a2 8e   82 e3 91 96 eb 8f 39 ae
00000050 | 7a 5a 89 68 e0 b3 e2 d6   9f 00 b3 57 96 a5 c2 12
00000060 | 90 cd 0f ee bf 00 c4 0a   79 82 07 04 eb 2d eb 71
00000070 | 96 d0 ab 76 2a 72 47 98   33 c6 e3 a8 7d 5c 8a

Tddli_TransmitData, success
Command ReadPubEK Success

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 12 00 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | 2a 3e 40 b9 c4 f3 b9 09   88 3e 2c 5e 47 f8 92 93
00000040 | 8b e8 f0 2e 1b 4c c6 32   b3 dc b7 25 5f 90 91 bb

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 e2 bf bf e7 da df
00000010 | f5 b4 a9 61 cc 18 dd 48   1b 82 74 0e db f4 c8 ff
00000020 | 2f 7a 42 a8 b8 0e ee c4   42 fc b0 22 a4 98 75 88
00000030 | f5 af 1d dc 46 18 fa a3   61 9d f6 c9 a6 95 54 29
00000040 | 19 2f e9 8c 76 78 25 4d   59 77 09 2c aa dc 52 74
00000050 | 57 7a

Tddli_TransmitData, success
TCM_APCreate Success

**tcm_ecc_encrypt**  g_uNumbits = 256, CIPHER_LEN=129
***** EC_POINT_set_point!
pPlaintext_in:
00000000 | 4d 59 30 6c 73 97 e0 6d   e3 cd 82 a1 4a 92 6f ba
00000010 | fe d4 43 52 ad 3e f8 8a   06 f5 cb e6 00 af 3d cf

pPubkey_in:
00000000 | 04 cf dc c8 5e e5 50 47   ab f3 f1 f0 03 ab 44 62
00000010 | 84 c7 e6 14 56 86 ee c5   7b ce f3 ba 62 5f 47 52
00000020 | 1f 05 05 8f 21 45 25 68   a2 8e 82 e3 91 96 eb 8f
00000030 | 39 ae 7a 5a 89 68 e0 b3   e2 d6 9f 00 b3 57 96 a5
00000040 | c2

***** ECC_Encrypt success!
encOwnerAuth:
00000000 | 04 59 71 d1 4b 29 fa 8e   db f6 5a 3a be 0c 5d c8
00000010 | 9c 3b d7 90 ab 85 07 3b   3e a3 2a 46 23 e0 1a 14
00000020 | 38 44 25 e6 2f e8 88 92   e2 d4 c0 39 b9 15 74 ce
00000030 | e0 16 97 9e 89 82 7f a3   3a 7f 6a d3 2b f4 c3 71
00000040 | 0d e2 03 2c d9 dc 08 11   c2 6d 4c 65 55 42 09 12
00000050 | 5c 13 f2 76 b4 f9 c4 d1   7b 59 b6 eb a4 41 08 3b
00000060 | 19 c3 18 d5 1e d4 5c 0d   25 3a 0f 1a 8e d4 c7 ef
00000070 | 45 1a 50 a1 5b 6d 43 6e   7f 0f bd 99 46 ae 5e c8
00000080 | a4

**tcm_ecc_encrypt**  g_uNumbits = 256, CIPHER_LEN=129
***** EC_POINT_set_point!
pPlaintext_in:
00000000 | 4d 59 30 6c 73 97 e0 6d   e3 cd 82 a1 4a 92 6f ba
00000010 | fe d4 43 52 ad 3e f8 8a   06 f5 cb e6 00 af 3d cf

pPubkey_in:
00000000 | 04 cf dc c8 5e e5 50 47   ab f3 f1 f0 03 ab 44 62
00000010 | 84 c7 e6 14 56 86 ee c5   7b ce f3 ba 62 5f 47 52
00000020 | 1f 05 05 8f 21 45 25 68   a2 8e 82 e3 91 96 eb 8f
00000030 | 39 ae 7a 5a 89 68 e0 b3   e2 d6 9f 00 b3 57 96 a5
00000040 | c2

***** ECC_Encrypt success!
encOwnerAuth:
00000000 | 04 10 45 08 bd b4 4e a7   d1 57 45 bc 8e d7 c3 83
00000010 | 77 97 46 ae ba de 01 98   d8 14 73 cb c9 a4 89 09
00000020 | 5a 50 9d 0b 4f ee 48 b9   64 8d d1 82 d2 00 f9 e9
00000030 | 25 60 99 3c 50 77 36 60   75 06 5a 74 fa 6d d8 98
00000040 | 32 d6 97 8e 7a c2 6c fe   8a b4 cb 59 c0 df 8e 2c
00000050 | c6 b6 7e 54 a3 8e 77 bb   00 d3 5b e5 1f 14 92 a4
00000060 | 92 55 55 8b 57 7b 8e 6b   ec 1a 26 de 31 f4 96 47
00000070 | 96 b9 29 39 c1 ef de 87   9a 2a f3 a5 d2 93 fb 10
00000080 | b5

input data:
00000000 | 00 c1 00 00 00 0a 00 00   80 ea

output data:
00000000 | 00 c4 00 00 00 0e 00 00   00 00 00 00 04 00

input data:
00000000 | 00 c1 00 00 00 12 00 00   80 eb 00 00 00 04 00 00
00000010 | 80 0d

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 10 00 00   80 eb 00 00 00 02 00 05

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 12 00 00   80 eb 00 00 00 04 00 00
00000010 | 00 81

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 8f 00 00   80 eb 00 00 00 81 04 59
00000010 | 71 d1 4b 29 fa 8e db f6   5a 3a be 0c 5d c8 9c 3b
00000020 | d7 90 ab 85 07 3b 3e a3   2a 46 23 e0 1a 14 38 44
00000030 | 25 e6 2f e8 88 92 e2 d4   c0 39 b9 15 74 ce e0 16
00000040 | 97 9e 89 82 7f a3 3a 7f   6a d3 2b f4 c3 71 0d e2
00000050 | 03 2c d9 dc 08 11 c2 6d   4c 65 55 42 09 12 5c 13
00000060 | f2 76 b4 f9 c4 d1 7b 59   b6 eb a4 41 08 3b 19 c3
00000070 | 18 d5 1e d4 5c 0d 25 3a   0f 1a 8e d4 c7 ef 45 1a
00000080 | 50 a1 5b 6d 43 6e 7f 0f   bd 99 46 ae 5e c8 a4

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 12 00 00   80 eb 00 00 00 04 00 00
00000010 | 00 81

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 8f 00 00   80 eb 00 00 00 81 04 10
00000010 | 45 08 bd b4 4e a7 d1 57   45 bc 8e d7 c3 83 77 97
00000020 | 46 ae ba de 01 98 d8 14   73 cb c9 a4 89 09 5a 50
00000030 | 9d 0b 4f ee 48 b9 64 8d   d1 82 d2 00 f9 e9 25 60
00000040 | 99 3c 50 77 36 60 75 06   5a 74 fa 6d d8 98 32 d6
00000050 | 97 8e 7a c2 6c fe 8a b4   cb 59 c0 df 8e 2c c6 b6
00000060 | 7e 54 a3 8e 77 bb 00 d3   5b e5 1f 14 92 a4 92 55
00000070 | 55 8b 57 7b 8e 6b ec 1a   26 de 31 f4 96 47 96 b9
00000080 | 29 39 c1 ef de 87 9a 2a   f3 a5 d2 93 fb 10 b5

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 4d 00 00   80 ec 00 00 00 3f 00 15
00000010 | 00 00 00 18 00 00 00 04   00 00 00 00 0c 00 08 00
00000020 | 01 00 00 00 1c 00 00 00   80 00 00 00 80 00 00 00
00000030 | 10 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000040 | 00 00 00 00 00 00 00 00   00 00 00 00 00

output data:
00000000 | 00 c4 00 00 00 2a 00 00   00 00 82 40 ec 75 01 b6
00000010 | 62 45 4d ac f0 7e 80 ad   04 c1 dd e6 14 0f 2d 0e
00000020 | c9 dd 8f 4e 28 ac 68 f7   3a cb

inMac:
00000000 | b4 64 9a 2a 07 b9 aa 24   fe d8 14 8e 42 19 a9 fd
00000010 | 45 ee 1b 8a 84 d0 57 38   0c 88 0e cc 5b 09 8b bc

tcm_ecc_encrypt smk success

input data:
00000000 | 00 c2 00 00 01 79 00 00   80 0d 00 05 00 00 00 81
00000010 | 04 59 71 d1 4b 29 fa 8e   db f6 5a 3a be 0c 5d c8
00000020 | 9c 3b d7 90 ab 85 07 3b   3e a3 2a 46 23 e0 1a 14
00000030 | 38 44 25 e6 2f e8 88 92   e2 d4 c0 39 b9 15 74 ce
00000040 | e0 16 97 9e 89 82 7f a3   3a 7f 6a d3 2b f4 c3 71
00000050 | 0d e2 03 2c d9 dc 08 11   c2 6d 4c 65 55 42 09 12
00000060 | 5c 13 f2 76 b4 f9 c4 d1   7b 59 b6 eb a4 41 08 3b
00000070 | 19 c3 18 d5 1e d4 5c 0d   25 3a 0f 1a 8e d4 c7 ef
00000080 | 45 1a 50 a1 5b 6d 43 6e   7f 0f bd 99 46 ae 5e c8
00000090 | a4 00 00 00 81 04 10 45   08 bd b4 4e a7 d1 57 45
000000a0 | bc 8e d7 c3 83 77 97 46   ae ba de 01 98 d8 14 73
000000b0 | cb c9 a4 89 09 5a 50 9d   0b 4f ee 48 b9 64 8d d1
000000c0 | 82 d2 00 f9 e9 25 60 99   3c 50 77 36 60 75 06 5a
000000d0 | 74 fa 6d d8 98 32 d6 97   8e 7a c2 6c fe 8a b4 cb
000000e0 | 59 c0 df 8e 2c c6 b6 7e   54 a3 8e 77 bb 00 d3 5b
000000f0 | e5 1f 14 92 a4 92 55 55   8b 57 7b 8e 6b ec 1a 26
00000100 | de 31 f4 96 47 96 b9 29   39 c1 ef de 87 9a 2a f3
00000110 | a5 d2 93 fb 10 b5 00 15   00 00 00 18 00 00 00 04
00000120 | 00 00 00 00 0c 00 08 00   01 00 00 00 1c 00 00 00
00000130 | 80 00 00 00 80 00 00 00   10 00 00 00 00 00 00 00
00000140 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000150 | 00 00 00 00 00 e2 bf bf   e7 b4 64 9a 2a 07 b9 aa
00000160 | 24 fe d8 14 8e 42 19 a9   fd 45 ee 1b 8a 84 d0 57
00000170 | 38 0c 88 0e cc 5b 09 8b   bc

output data:
00000000 | 00 c5 00 00 00 69 00 00   00 00 00 15 00 00 00 18
00000010 | 00 00 00 04 00 00 00 00   0c 00 08 00 01 00 00 00
00000020 | 1c 00 00 00 80 00 00 00   80 00 00 00 10 00 00 00
00000030 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000040 | 00 00 00 00 00 00 00 00   00 47 42 fb 0d 73 19 6a
00000050 | 4b 19 1f fe fd 64 17 1d   ad 62 70 92 c9 1d 21 df
00000060 | d2 61 7c 25 23 08 c1 eb   1c

Tddli_TransmitData, success
Command TakeOwnership Success

-------> begin TCM_Owner_APTerminate
sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 e2 bf bf e7 85 4c
00000010 | c2 11 f0 c2 a9 d3 cf ef   bf 2f e7 23 53 de 16 20
00000020 | 30 38 54 cf 73 22 f4 f5   1f 07 f2 e6 5c 4b

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

Command Terminate Success
TCM_TakeOwnership Success
```
### 3.2.5 验证授权信息
```
# ./tcm_test /vp 1234567890abcdef1234567890abcdef /dd

FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

passwd:
00000000 | 12 34 56 78 90 ab cd ef   12 34 56 78 90 ab cd ef

hash:
00000000 | 27 1f b6 70 63 53 dc 06   0a be ce a9 54 8e 7a 47
00000010 | 84 32 3f 12 68 e9 fd 7d   e5 1c 05 de 2d 05 16 7d

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 02 00 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | 70 a1 1b 61 73 47 42 d6   f8 ee 05 4a 22 e8 01 6c
00000040 | 5d 98 71 83 42 b7 6c 93   9a 71 87 cb 0b 8c d6 73

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 38 a2 e7 b3 a1 b9
00000010 | fe 64 d5 a6 70 a3 7e 3c   91 ac ee b3 da 2f 49 41
00000020 | 78 8f 53 a3 96 55 66 34   cb cf 70 68 1a 13 b6 59
00000030 | f4 2b 4c 41 09 fa 0d c9   92 1b 25 dc 65 c3 34 c7
00000040 | 77 0c 96 f5 30 97 98 81   8f 14 8a 68 67 23 03 5f
00000050 | 00 b5

TCM_Owner_APCreate success
Command TCM_Owner_APCreate Success
seq_APCreateOut:
00000000 | b6 59 f4 2b

input data:
00000000 | 00 c2 00 00 00 32 00 00   80 81 40 00 00 06 38 a2
00000010 | e7 b3 cc f8 9b f8 18 76   88 1b 54 5c 14 5a 56 c2
00000020 | 2f ec 57 7c a1 fb 77 8a   39 44 98 5e d0 aa 6a 72
00000030 | e3 ce

output data:
00000000 | 00 c5 00 00 00 7f 00 00   00 00 00 00 00 0b 00 06
00000010 | 00 01 00 00 00 04 00 00   01 00 00 00 00 41 04 89
00000020 | d7 62 8a 99 a0 cd ce 39   f5 c6 1a c8 bd 58 ed 75
00000030 | 51 7b 54 5c da 89 4f 36   06 20 bf ba 05 72 97 5d
00000040 | 19 a7 36 5e 11 90 8c 34   82 30 4e 27 c6 89 96 32
00000050 | ec c0 39 1d bf 57 08 03   02 5d fd 14 30 ed eb ef
00000060 | ac d2 f6 b1 ca 83 96 7c   56 1e 52 a5 88 6f ab fa
00000070 | 1f 26 7e 33 4e d6 17 0e   da ab 1e 7f 46 0e 1a

EK Pub:
00000000 | 00 00 00 0b 00 06 00 01   00 00 00 04 00 00 01 00
00000010 | 00 00 00 41 04 89 d7 62   8a 99 a0 cd ce 39 f5 c6
00000020 | 1a c8 bd 58 ed 75 51 7b   54 5c da 89 4f 36 06 20
00000030 | bf ba 05 72 97 5d 19 a7   36 5e 11 90 8c 34 82 30
00000040 | 4e

sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

Terminate Hash:
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 38 a2 e7 b3 ac bb
00000010 | 6b 07 ad 69 b4 ff d7 de   c2 ee 61 95 bd 54 d9 e9
00000020 | b4 7c 4f aa ae 5c 23 3c   18 6c 93 69 c3 7f

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

TCM_Owner_APTerminate Success
TCM_OwnerReadEKPub Success
```
### 3.2.6 修改授权信息
```
# ./tcm_test /cp zxcvbnm asdfghjkl /dd

FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

sm3 data
00000000 | a8 c6 be 3d

SM3_soft result
00000000 | 16 47 b6 30 c5 84 2c 22   54 fd 14 23 64 7b 14 a9
00000010 | 2e e9 73 42 c5 c3 05 2b   5d ff 5b 6c b1 1f a8 a2

hash:
00000000 | 16 47 b6 30 c5 84 2c 22   54 fd 14 23 64 7b 14 a9
00000010 | 2e e9 73 42 c5 c3 05 2b   5d ff 5b 6c b1 1f a8 a2

sm3 data
00000000 | a3 df 78 ab 3c

SM3_soft result
00000000 | 28 40 46 6c f1 61 d8 5a   32 bc a6 76 d7 40 fd fc
00000010 | 76 db 99 94 cd 42 b9 c6   70 b5 8e c1 0e c8 3f dc

hash:
00000000 | 28 40 46 6c f1 61 d8 5a   32 bc a6 76 d7 40 fd fc
00000010 | 76 db 99 94 cd 42 b9 c6   70 b5 8e c1 0e c8 3f dc

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 02 00 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | e9 28 ee 4a 72 66 d3 a3   27 92 2e e0 84 72 ce 50
00000040 | b7 b6 8e c3 bc f5 9d e7   75 8b 7a dd 6a 9d 77 0a

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 6a 43 69 68 8e c6
00000010 | ff 31 d7 f5 c4 76 a0 ae   73 2f 43 70 76 99 28 4a
00000020 | 1d 1f 57 df eb 19 2e 6f   a0 b6 89 4b d7 4e 79 1b
00000030 | c6 7e 02 b6 95 9b c8 c0   82 2b 95 5e 76 35 c1 24
00000040 | 7e 2f 71 f9 9e b7 7c 0d   48 99 0d 21 d7 29 ac 3c
00000050 | 99 d4
------------------------------------------------------------------------------
Command TCM_Owner_APCreate Success
seq_APCreateOut:
00000000 | 79 1b c6 7e

sm3 data
00000000 | 00 00 80 81 40 00 00 06

SM3_soft result
00000000 | 95 64 12 ec 48 44 b6 9f   90 c7 e0 a4 10 88 e8 08
00000010 | f9 32 25 1e 55 ad 6c 08   a1 b7 83 11 e3 39 37 12

input data:
00000000 | 00 c2 00 00 00 32 00 00   80 81 40 00 00 06 6a 43
00000010 | 69 68 9b d8 3f 8a 4f b5   9e 93 a4 35 e2 2c 52 6a
00000020 | ef 7f a7 e7 3f 33 0c 01   40 e7 52 5f a4 22 11 ae
00000030 | f6 8d

output data:
00000000 | 00 c5 00 00 00 7f 00 00   00 00 00 00 00 0b 00 06
00000010 | 00 01 00 00 00 04 00 00   01 00 00 00 00 41 04 cf
00000020 | dc c8 5e e5 50 47 ab f3   f1 f0 03 ab 44 62 84 c7
00000030 | e6 14 56 86 ee c5 7b ce   f3 ba 62 5f 47 52 1f 05
00000040 | 05 8f 21 45 25 68 a2 8e   82 e3 91 96 eb 8f 39 ae
00000050 | 7a 5a 89 68 e0 b3 e2 d6   9f 00 b3 57 96 a5 c2 d4
00000060 | 41 93 34 2c c5 44 79 e7   ed 57 dd f2 0f 82 ad aa
00000070 | 8d 98 8f c3 19 5c 84 5f   08 22 38 d0 05 e7 3e
------------------------------------------------------------------------------
EK Pub:
00000000 | 00 00 00 0b 00 06 00 01   00 00 00 04 00 00 01 00
00000010 | 00 00 00 41 04 cf dc c8   5e e5 50 47 ab f3 f1 f0
00000020 | 03 ab 44 62 84 c7 e6 14   56 86 ee c5 7b ce f3 ba
00000030 | 62 5f 47 52 1f 05 05 8f   21 45 25 68 a2 8e 82 e3
00000040 | 91

sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

Terminate Hash:
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 6a 43 69 68 24 08
00000010 | da c5 9d d0 5e 94 41 4a   27 f6 5d 90 2d 30 99 e5
00000020 | 70 75 d7 ba b6 14 e4 04   e9 06 ff 8a b6 fc

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00
------------------------------------------------------------------------------
input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 02 40 00 00 01
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | e9 28 ee 4a 72 66 d3 a3   27 92 2e e0 84 72 ce 50
00000040 | b7 b6 8e c3 bc f5 9d e7   75 8b 7a dd 6a 9d 77 0a

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 98 95 30 6d b7 ce
00000010 | cf de 52 3c bf 01 4f ad   bc ec 6f 81 83 83 69 90
00000020 | d7 54 35 14 64 2a e3 c0   ac 81 9a 50 77 fe c8 22
00000030 | e0 fe 76 fe e5 74 9f ab   61 6d 29 09 1e de d8 e6
00000040 | 88 41 c0 41 5d 1e 2b 91   43 8a 5d 08 90 cc 0d de
00000050 | 6c f2
------------------------------------------------------------------------------
sm3 data
00000000 | 72 56 33 b4 10 75 7f b0   f0 53 a7 b7 6f 7f 05 5e
00000010 | f9 84 0b 4c a1 80 c9 0d   1f ac 97 57 14 7b 8d f4
00000020 | c8 22 e0 fe

SM3_soft result
00000000 | 03 ed 5b e6 13 f3 d5 95   9a 85 76 38 14 00 5f d7
00000010 | 7d 71 a2 bd 2c 4f 84 ae   c6 f1 59 03 22 49 8e 69

sm3 data
00000000 | 00 00 80 10 00 04 2b ad   1d 8a e2 92 0d cf a8 39
00000010 | d0 4e c3 40 a2 2b 0b aa   3b 29 e1 0d 3d 68 b6 44
00000020 | d7 c2 2c 81 b1 b5 00 02

SM3_soft result
00000000 | 96 e1 c2 6e 5e d8 20 dd   05 d3 c4 d6 0c 01 8f 36
00000010 | 09 0f be f3 ae cb 16 49   51 91 b8 d8 ba ce 36 5a

input data:
00000000 | 00 c2 00 00 00 52 00 00   80 10 00 04 2b ad 1d 8a
00000010 | e2 92 0d cf a8 39 d0 4e   c3 40 a2 2b 0b aa 3b 29
00000020 | e1 0d 3d 68 b6 44 d7 c2   2c 81 b1 b5 00 02 98 95
00000030 | 30 6d fe 4a db f7 46 e3   fe 81 75 e3 10 98 9f 47
00000040 | 64 ca 9a 76 9c bf 67 8e   1b ce 3e 45 84 67 8e cb
00000050 | 9a 4e

output data:
00000000 | 00 c5 00 00 00 2a 00 00   00 00 80 88 5b cf 1e b4
00000010 | 82 ca 48 1f fa 18 d3 67   d7 88 80 c4 3d 8a 6d 07
00000020 | 1d 54 13 d9 5d ba 56 51   1d ae
------------------------------------------------------------------------------
TCM_ChangeAuthOwner Success
```
### 3.2.7 创建SM2非对称密钥
```
# ./tcm_test /cwk zxcvbnm /dd
FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

sm3 data
00000000 | a8 c6 be 3d

SM3_soft result
00000000 | 16 47 b6 30 c5 84 2c 22   54 fd 14 23 64 7b 14 a9
00000010 | 2e e9 73 42 c5 c3 05 2b   5d ff 5b 6c b1 1f a8 a2

sm2_keyinfo
00000000 | 00 15 00 00 00 10 00 00   00 04 00 00 00 00 0b 00
00000010 | 04 00 05 00 00 00 04 00   00 01 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 04 40 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | e9 28 ee 4a 72 66 d3 a3   27 92 2e e0 84 72 ce 50
00000040 | b7 b6 8e c3 bc f5 9d e7   75 8b 7a dd 6a 9d 77 0a

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 22 6b a2 7f 06 a7
00000010 | fc bc 2b a5 08 6f 20 df   c7 99 7f 2b c0 a6 dd 31
00000020 | f2 a3 5d f1 01 48 74 f8   5a 02 f8 3c 5a 66 e3 01
00000030 | d3 a0 ea 0c 87 dd ff 19   e7 ff 10 8e 86 dd 8d 87
00000040 | 05 ba 4d 2a d1 c0 d4 14   c1 f8 f2 9d 4d 31 d3 cf
00000050 | ae 81

Command TCM_Owner_APCreate success
seq_APCreateOut:
00000000 | e3 01 d3 a0

sm3 data
00000000 | d8 f0 a2 38 5e 00 18 1a   72 26 55 62 cc 76 25 ac
00000010 | af 5e 4f 85 2e 5b 66 5a   fe 73 37 3a 41 de 32 98
00000020 | e3 01 d3 a0

SM3_soft result
00000000 | a6 d0 d4 93 b9 1c 59 88   7a 00 4e 89 eb 6b e4 8b
00000010 | 72 49 eb 41 36 26 91 0c   aa 61 9a 57 65 6b 7c b7

keyauth
00000000 | b0 97 62 a3 7c 98 75 aa   2e fd 5a aa 8f 10 f0 22
00000010 | 5c a0 98 03 f3 e5 94 27   f7 9e c1 3b d4 74 d4 15

calculate hash begin
sm3 data
00000000 | 00 00 80 1f b0 97 62 a3   7c 98 75 aa 2e fd 5a aa
00000010 | 8f 10 f0 22 5c a0 98 03   f3 e5 94 27 f7 9e c1 3b
00000020 | d4 74 d4 15 b0 97 62 a3   7c 98 75 aa 2e fd 5a aa
00000030 | 8f 10 f0 22 5c a0 98 03   f3 e5 94 27 f7 9e c1 3b
00000040 | d4 74 d4 15 00 15 00 00   00 10 00 00 00 04 00 00
00000050 | 00 00 0b 00 04 00 05 00   00 00 04 00 00 01 00 00
00000060 | 00 00 00 00 00 00 00 00   00 00 00

SM3_soft result
00000000 | 7a 86 94 0d 1f 55 3c 01   44 37 97 c3 36 72 8e 3a
00000010 | 24 4a 85 92 21 43 66 fe   f0 e3 94 30 f2 45 3a 6e

inMac
00000000 | 61 70 77 74 02 46 fd 4e   3e 87 22 75 78 fe 4e 90
00000010 | e9 12 95 62 4c e4 64 22   43 4b ac f1 a2 7a 26 b8

input data:
00000000 | 00 c2 00 00 00 99 00 00   80 1f 40 00 00 00 b0 97
00000010 | 62 a3 7c 98 75 aa 2e fd   5a aa 8f 10 f0 22 5c a0
00000020 | 98 03 f3 e5 94 27 f7 9e   c1 3b d4 74 d4 15 b0 97
00000030 | 62 a3 7c 98 75 aa 2e fd   5a aa 8f 10 f0 22 5c a0
00000040 | 98 03 f3 e5 94 27 f7 9e   c1 3b d4 74 d4 15 00 15
00000050 | 00 00 00 10 00 00 00 04   00 00 00 00 0b 00 04 00
00000060 | 05 00 00 00 04 00 00 01   00 00 00 00 00 00 00 00
00000070 | 00 00 00 00 00 22 6b a2   7f 61 70 77 74 02 46 fd
00000080 | 4e 3e 87 22 75 78 fe 4e   90 e9 12 95 62 4c e4 64
00000090 | 22 43 4b ac f1 a2 7a 26   b8

output data:
00000000 | 00 c5 00 00 01 22 00 00   00 00 00 15 00 00 00 10
00000010 | 00 00 00 04 00 00 00 00   0b 00 04 00 05 00 00 00
00000020 | 04 00 00 01 00 00 00 00   00 00 00 00 41 04 50 83
00000030 | 39 b4 1e 68 2d f4 aa 88   df ef a7 71 7f b8 c8 74
00000040 | 53 65 93 af a6 44 e3 55   9b dd 5f b5 fc 99 5e 74
00000050 | 96 8a c9 4f d1 a0 57 25   e7 69 9b 8c e9 5b 4d ba
00000060 | 0f 51 a3 b5 21 8a d1 03   16 3a 62 52 d2 d3 00 00
00000070 | 00 90 65 ad 6d 23 74 e5   d9 fd 8d e6 3f e1 bb 9e
00000080 | 6a 73 0b 7e 48 09 82 09   fa e8 24 1c a8 18 c2 4a
00000090 | 6b e0 0a 68 93 9a f6 a1   9f a2 12 90 3c b5 f4 00
000000a0 | ec 4b 87 14 13 97 44 a8   58 cf f4 9d da 81 81 cb
000000b0 | 87 54 e1 de 69 bf dc 10   65 91 33 6d b8 36 8b cb
000000c0 | ec f5 12 12 4f 45 19 6f   bc d1 82 00 4c 20 2e 38
000000d0 | af 75 fc ff 4f c9 df 4b   52 21 70 7e ed 83 83 3d
000000e0 | 4a cc ce ea 7e de 72 4b   cf 95 6d 10 7b c0 40 bc
000000f0 | 51 b2 7d 6b d1 f3 f8 e6   f0 dd 54 18 27 b1 e3 56
00000100 | 73 a9 59 86 68 d4 24 e9   0a 43 db bc e7 26 6c 6e
00000110 | f3 47 10 46 44 78 85 7c   b1 8d a2 c3 30 af 5a ee
00000120 | 22 82

TCM_CreateWrapKey success

-------> begin TCM_Owner_APTerminate
sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 22 6b a2 7f ae bc
00000010 | cf c5 21 bd 28 fe 97 4c   79 e9 25 cd 21 0b c4 90
00000020 | 20 59 d6 24 15 54 e7 3a   a2 1a 33 7b 25 7e

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

tcm_createwrapkey Success
input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 04 40 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | e9 28 ee 4a 72 66 d3 a3   27 92 2e e0 84 72 ce 50
00000040 | b7 b6 8e c3 bc f5 9d e7   75 8b 7a dd 6a 9d 77 0a

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 1b b6 70 35 72 29
00000010 | 79 b7 a4 09 ca af 07 50   aa 2c 3a 1a 78 a3 18 77
00000020 | 2c 47 7f 54 12 87 84 0b   99 0a 40 25 96 7a 9c 80
00000030 | 0a c2 a0 ba 2b 7a eb de   d9 e2 fe dd 26 36 aa dd
00000040 | fc f2 9a 78 e5 25 01 ea   0e c0 50 f7 cf 74 3d 5e
00000050 | 51 d4

Command TCM_Owner_APCreate success
sm3 data
00000000 | 00 00 80 ef 00 15 00 00   00 10 00 00 00 04 00 00
00000010 | 00 00 0b 00 04 00 05 00   00 00 04 00 00 01 00 00
00000020 | 00 00 00 00 00 00 41 04   50 83 39 b4 1e 68 2d f4
00000030 | aa 88 df ef a7 71 7f b8   c8 74 53 65 93 af a6 44
00000040 | e3 55 9b dd 5f b5 fc 99   5e 74 96 8a c9 4f d1 a0
00000050 | 57 25 e7 69 9b 8c e9 5b   4d ba 0f 51 a3 b5 21 8a
00000060 | d1 03 16 3a 62 52 d2 d3   00 00 00 90 65 ad 6d 23
00000070 | 74 e5 d9 fd 8d e6 3f e1   bb 9e 6a 73 0b 7e 48 09
00000080 | 82 09 fa e8 24 1c a8 18   c2 4a 6b e0 0a 68 93 9a
00000090 | f6 a1 9f a2 12 90 3c b5   f4 00 ec 4b 87 14 13 97
000000a0 | 44 a8 58 cf f4 9d da 81   81 cb 87 54 e1 de 69 bf
000000b0 | dc 10 65 91 33 6d b8 36   8b cb ec f5 12 12 4f 45
000000c0 | 19 6f bc d1 82 00 4c 20   2e 38 af 75 fc ff 4f c9
000000d0 | df 4b 52 21 70 7e ed 83   83 3d 4a cc ce ea 7e de
000000e0 | 72 4b cf 95 6d 10 7b c0   40 bc 51 b2 7d 6b d1 f3
000000f0 | f8 e6 f0 dd 54 18 27 b1   e3 56 73 a9

SM3_soft result
00000000 | f9 6b bf b3 93 f6 5a fb   23 47 db 67 d7 97 fe fd
00000010 | dd e1 c8 c2 3e 29 79 3b   54 d0 7b 22 a4 41 ca 45

inMac
00000000 | c2 39 ae 58 2c 81 59 3f   c8 88 79 f2 e8 5e d3 c1
00000010 | 4b cc 20 bf da de e8 c2   78 6d 53 7f ad 49 08 6e

input data:
00000000 | 00 c2 00 00 01 2a 00 00   80 ef 40 00 00 00 00 15
00000010 | 00 00 00 10 00 00 00 04   00 00 00 00 0b 00 04 00
00000020 | 05 00 00 00 04 00 00 01   00 00 00 00 00 00 00 00
00000030 | 41 04 50 83 39 b4 1e 68   2d f4 aa 88 df ef a7 71
00000040 | 7f b8 c8 74 53 65 93 af   a6 44 e3 55 9b dd 5f b5
00000050 | fc 99 5e 74 96 8a c9 4f   d1 a0 57 25 e7 69 9b 8c
00000060 | e9 5b 4d ba 0f 51 a3 b5   21 8a d1 03 16 3a 62 52
00000070 | d2 d3 00 00 00 90 65 ad   6d 23 74 e5 d9 fd 8d e6
00000080 | 3f e1 bb 9e 6a 73 0b 7e   48 09 82 09 fa e8 24 1c
00000090 | a8 18 c2 4a 6b e0 0a 68   93 9a f6 a1 9f a2 12 90
000000a0 | 3c b5 f4 00 ec 4b 87 14   13 97 44 a8 58 cf f4 9d
000000b0 | da 81 81 cb 87 54 e1 de   69 bf dc 10 65 91 33 6d
000000c0 | b8 36 8b cb ec f5 12 12   4f 45 19 6f bc d1 82 00
000000d0 | 4c 20 2e 38 af 75 fc ff   4f c9 df 4b 52 21 70 7e
000000e0 | ed 83 83 3d 4a cc ce ea   7e de 72 4b cf 95 6d 10
000000f0 | 7b c0 40 bc 51 b2 7d 6b   d1 f3 f8 e6 f0 dd 54 18
00000100 | 27 b1 e3 56 73 a9 1b b6   70 35 c2 39 ae 58 2c 81
00000110 | 59 3f c8 88 79 f2 e8 5e   d3 c1 4b cc 20 bf da de
00000120 | e8 c2 78 6d 53 7f ad 49   08 6e

output data:
00000000 | 00 c5 00 00 00 2e 00 00   00 00 c4 28 57 2e 6c 0f
00000010 | 6c fc 58 ba f4 51 4f 18   83 66 18 e0 17 7e 53 d7
00000020 | 9d 97 ea 10 51 a1 47 d1   03 39 7a bc 11 8e

TCM_LoadKey success

-------> begin TCM_Owner_APTerminate
sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 1b b6 70 35 b1 47
00000010 | 4f 37 d1 bb 4d d5 82 86   8a 70 2c f5 ca 03 39 48
00000020 | 83 01 dc fa ff 46 c6 49   b8 4d cf 0a ab 20

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00
```
### 3.2.8 获取SM2公钥
```
# ./tcm_test /gpk zxcvbnm /dd
FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

sm3 data
00000000 | a8 c6 be 3d

SM3_soft result
00000000 | 16 47 b6 30 c5 84 2c 22   54 fd 14 23 64 7b 14 a9
00000010 | 2e e9 73 42 c5 c3 05 2b   5d ff 5b 6c b1 1f a8 a2

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 04 40 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | e9 28 ee 4a 72 66 d3 a3   27 92 2e e0 84 72 ce 50
00000040 | b7 b6 8e c3 bc f5 9d e7   75 8b 7a dd 6a 9d 77 0a

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 18 a8 d7 a1 8c 3d
00000010 | 8f 64 25 63 d3 13 22 f6   6a 38 3e af 81 d3 e4 c0
00000020 | 0e 6d b2 20 13 3d 00 42   3c 1a 01 d6 c9 b7 df 81
00000030 | 4e fe f9 15 c0 78 b6 9d   97 44 18 26 b1 82 9b 29
00000040 | f6 4f a9 5f c7 83 b1 a9   2b 1c 3a dc a4 d8 e6 38
00000050 | 8b 59

Command TCM_Owner_APCreate success
sm3 data
00000000 | 00 00 80 21

SM3_soft result
00000000 | 66 b5 90 83 44 00 68 17   ae 21 3c b9 8e 54 36 5b
00000010 | a2 1a d4 5a 86 e7 c2 fd   51 f5 7b 78 30 d7 24 c0

input data:
00000000 | 00 c2 00 00 00 32 00 00   80 21 c4 28 57 2e 18 a8
00000010 | d7 a1 08 cd 33 d4 fe aa   5e 47 53 90 ec 64 36 22
00000020 | d6 8c f0 e4 46 62 ff a3   22 30 81 cf b8 5f ba 1f
00000030 | 6d 98

output data:
00000000 | 00 c5 00 00 00 7f 00 00   00 00 00 00 00 0b 00 04
00000010 | 00 05 00 00 00 04 00 00   01 00 00 00 00 41 04 50
00000020 | 83 39 b4 1e 68 2d f4 aa   88 df ef a7 71 7f b8 c8
00000030 | 74 53 65 93 af a6 44 e3   55 9b dd 5f b5 fc 99 5e
00000040 | 74 96 8a c9 4f d1 a0 57   25 e7 69 9b 8c e9 5b 4d
00000050 | ba 0f 51 a3 b5 21 8a d1   03 16 3a 62 52 d2 d3 a7
00000060 | 41 a0 d4 e3 27 05 d0 5c   e7 3d 1b 3b d6 d8 04 a5
00000070 | 2c b1 76 16 21 6d 5c 02   e7 ea ca ea fd 5e ff

TCM_GetPubKey success

-------> begin TCM_Owner_APTerminate
sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 18 a8 d7 a1 19 a9
00000010 | 4f b9 04 5c 95 13 4b 09   2d 75 c1 8b b9 88 cf 8e
00000020 | 8d d8 3b d1 0f 73 54 bc   89 c0 33 6e 79 da

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

sm2 pubkey
00000000 | 00 00 00 0b 00 04 00 05   00 00 00 04 00 00 01 00
00000010 | 00 00 00 41 04 50 83 39   b4 1e 68 2d f4 aa 88 df
00000020 | ef a7 71 7f b8 c8 74 53   65 93 af a6 44 e3 55 9b
00000030 | dd 5f b5 fc 99 5e 74 96   8a c9 4f d1 a0 57 25 e7
00000040 | 69 9b 8c e9 5b 4d ba 0f   51 a3 b5 21 8a d1 03 16
00000050 | 3a 62 52 d2 d3
```
### 3.2.9 加载SM4对称密钥
```
# ./tcm_test /sm4 qwerty /dd

FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

sm3 data
00000000 | 17 e2 49

SM3_soft result
00000000 | 79 7d 0c 9b 79 92 1a 6a   a8 08 a9 a1 87 c6 f7 cd
00000010 | 4e dd 72 e9 6e df 18 d7   5a 6a 79 c5 73 88 1c 7e

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 04 00 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | 19 43 10 de 1c b8 cc 01   fd 95 6e f4 64 d1 f0 2a
00000040 | 06 fd f7 dc 20 20 4b f0   cc 77 5f ad 19 bf 63 3c

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 c1 4c 04 44 e8 8f
00000010 | e8 b6 f3 0c 94 b4 07 d8   d7 71 3e 6b 41 61 2e 43
00000020 | db b9 2d 5a 3f fa a1 aa   f0 98 cc 4a 9d 2c 46 ca
00000030 | 91 06 06 2f 28 69 67 0b   85 21 48 aa 92 be b1 a4
00000040 | 6b dd 5c 3f b1 11 5a cf   7b ad 25 0e 06 e8 26 11
00000050 | cd 6a

Command TCM_Owner_APCreate success
sm3 data
00000000 | dc 0d 24 70 aa a4 2b ff   b7 be d8 96 fb 22 db b2
00000010 | bf 62 4a 47 c7 cf 8b f0   90 1f c1 fc 7a a8 79 b9
00000020 | 46 ca 91 06

SM3_soft result
00000000 | 1c d8 78 99 2e 17 10 b8   0b 95 2e fe bf 63 c9 97
00000010 | 87 8a 70 07 da 28 12 57   c4 81 02 b8 4b a5 1e 4a

keyauth
00000000 | 1c d8 78 99 2e 17 10 b8   0b 95 2e fe bf 63 c9 97
00000010 | 87 8a 70 07 da 28 12 57   c4 81 02 b8 4b a5 1e 4a

sm3 data
00000000 | 00 00 80 1f 1c d8 78 99   2e 17 10 b8 0b 95 2e fe
00000010 | bf 63 c9 97 87 8a 70 07   da 28 12 57 c4 81 02 b8
00000020 | 4b a5 1e 4a 1c d8 78 99   2e 17 10 b8 0b 95 2e fe
00000030 | bf 63 c9 97 87 8a 70 07   da 28 12 57 c4 81 02 b8
00000040 | 4b a5 1e 4a 00 15 00 00   00 19 00 00 00 00 00 00
00000050 | 00 00 0c 00 08 00 01 00   00 00 1c 00 00 00 80 00
00000060 | 00 00 80 00 00 00 10 00   00 00 00 00 00 00 00 00
00000070 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000080 | 00 00 53 00 00 00 00 00   00 00 00 00 00 00 00 00
00000090 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
000000a0 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
000000b0 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
000000c0 | 00 00 00 00 00 10 d4 30   cc 5d b0 29 25 51 3e b9
000000d0 | c7 de f6 bb 4e be

SM3_soft result
00000000 | d6 79 c3 08 0a 63 77 9b   b5 98 51 b1 75 21 a3 ba
00000010 | d6 ac 17 aa aa d2 5c b0   b1 91 50 ee 18 f8 f6 53

input data:
00000000 | 00 c2 00 00 01 04 00 00   80 1f 40 00 00 00 1c d8
00000010 | 78 99 2e 17 10 b8 0b 95   2e fe bf 63 c9 97 87 8a
00000020 | 70 07 da 28 12 57 c4 81   02 b8 4b a5 1e 4a 1c d8
00000030 | 78 99 2e 17 10 b8 0b 95   2e fe bf 63 c9 97 87 8a
00000040 | 70 07 da 28 12 57 c4 81   02 b8 4b a5 1e 4a 00 15
00000050 | 00 00 00 19 00 00 00 00   00 00 00 00 0c 00 08 00
00000060 | 01 00 00 00 1c 00 00 00   80 00 00 00 80 00 00 00
00000070 | 10 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000080 | 00 00 00 00 00 00 00 00   00 00 00 00 53 00 00 00
00000090 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
000000a0 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
000000b0 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
000000c0 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 10
000000d0 | d4 30 cc 5d b0 29 25 51   3e b9 c7 de f6 bb 4e be
000000e0 | c1 4c 04 44 f1 9f e2 f0   97 2b 5c cc cb 9b f3 6b
000000f0 | 05 2f 5c 62 0e cb a8 f1   85 50 a8 08 ed a1 5f 9c
00000100 | 79 68 8e 88

output data:
00000000 | 00 c5 00 00 00 c9 00 00   00 00 00 15 00 00 00 19
00000010 | 00 00 00 00 00 00 00 00   0c 00 08 00 01 00 00 00
00000020 | 1c 00 00 00 80 00 00 00   80 00 00 00 10 00 00 00
00000030 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000040 | 00 00 00 00 00 00 00 00   60 7c 22 9f f5 f3 05 3d
00000050 | d9 99 49 59 bf 91 7d f7   f9 92 e0 3a 3c 3a 0e 7b
00000060 | 8d b7 2c 38 84 aa df e9   dd 88 67 bd f6 27 26 a0
00000070 | 6c a4 a5 ec 68 db 7f ef   cb 9b 37 11 08 5b 40 07
00000080 | 5a 8b aa 08 7c 64 f1 1b   78 d1 33 4f 86 43 d3 4a
00000090 | c3 73 35 2d 54 a6 7c 77   0f 7f 6c 0a 3b c8 78 03
000000a0 | aa 30 fa 67 9a 64 87 e6   07 ee 8c 49 a3 f8 d6 c2
000000b0 | 6a a2 9a 52 ed fc b3 4e   7b 9d 93 1e 61 41 89 20
000000c0 | 4a 59 fa ca 03 a1 7d fd   54

TCM_WrapKey success

-------> begin TCM_Owner_APTerminate
sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 c1 4c 04 44 20 3c
00000010 | ba d5 cc ac de 04 ae b2   1f e2 a1 0a 49 ab 13 c7
00000020 | f0 72 f3 39 09 86 fa 7d   b2 f3 30 3c 2d ed

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 04 40 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | 19 43 10 de 1c b8 cc 01   fd 95 6e f4 64 d1 f0 2a
00000040 | 06 fd f7 dc 20 20 4b f0   cc 77 5f ad 19 bf 63 3c

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 70 0b 37 f2 1e 4e
00000010 | 5b df 10 1f f6 53 da d1   bf 43 fc 76 c7 43 ca 6c
00000020 | c1 06 b4 57 42 89 71 a9   da 62 01 c2 f2 38 12 c0
00000030 | e5 d8 43 22 52 00 b4 42   05 85 01 cd 11 4e 49 d8
00000040 | e6 fb f8 72 3f ed 54 d8   bf db ec b4 77 c9 94 d6
00000050 | 6f 57

Command TCM_Owner_APCreate success
sm3 data
00000000 | 00 00 80 ef 00 15 00 00   00 19 00 00 00 00 00 00
00000010 | 00 00 0c 00 08 00 01 00   00 00 1c 00 00 00 80 00
00000020 | 00 00 80 00 00 00 10 00   00 00 00 00 00 00 00 00
00000030 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000040 | 00 00 60 7c 22 9f f5 f3   05 3d d9 99 49 59 bf 91
00000050 | 7d f7 f9 92 e0 3a 3c 3a   0e 7b 8d b7 2c 38 84 aa
00000060 | df e9 dd 88 67 bd f6 27   26 a0 6c a4 a5 ec 68 db
00000070 | 7f ef cb 9b 37 11 08 5b   40 07 5a 8b aa 08 7c 64
00000080 | f1 1b 78 d1 33 4f 86 43   d3 4a c3 73 35 2d 54 a6
00000090 | 7c 77 0f 7f 6c 0a 3b c8   78 03 aa 30 fa 67 9a 64
000000a0 | 87 e6 07

SM3_soft result
00000000 | ff 31 41 78 04 a7 ab 5f   2a f6 5c c1 9a ab 2a 13
00000010 | b7 3a 17 35 5f ae 42 d4   43 14 0b 18 29 a6 f9 a8

inMac
00000000 | 00 ea 84 6c e4 f3 31 57   94 1b f9 d2 84 3b 5f e7
00000010 | 37 30 7b 03 78 f5 51 47   87 45 bf 39 fc 3e 13 84

input data:
00000000 | 00 c2 00 00 00 d1 00 00   80 ef 40 00 00 00 00 15
00000010 | 00 00 00 19 00 00 00 00   00 00 00 00 0c 00 08 00
00000020 | 01 00 00 00 1c 00 00 00   80 00 00 00 80 00 00 00
00000030 | 10 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000040 | 00 00 00 00 00 00 00 00   00 00 00 00 60 7c 22 9f
00000050 | f5 f3 05 3d d9 99 49 59   bf 91 7d f7 f9 92 e0 3a
00000060 | 3c 3a 0e 7b 8d b7 2c 38   84 aa df e9 dd 88 67 bd
00000070 | f6 27 26 a0 6c a4 a5 ec   68 db 7f ef cb 9b 37 11
00000080 | 08 5b 40 07 5a 8b aa 08   7c 64 f1 1b 78 d1 33 4f
00000090 | 86 43 d3 4a c3 73 35 2d   54 a6 7c 77 0f 7f 6c 0a
000000a0 | 3b c8 78 03 aa 30 fa 67   9a 64 87 e6 07 70 0b 37
000000b0 | f2 00 ea 84 6c e4 f3 31   57 94 1b f9 d2 84 3b 5f
000000c0 | e7 37 30 7b 03 78 f5 51   47 87 45 bf 39 fc 3e 13
000000d0 | 84

output data:
00000000 | 00 c5 00 00 00 2e 00 00   00 00 39 17 26 44 aa e3
00000010 | cf 51 db 0c c2 d2 7d b8   08 08 a2 38 a5 46 b2 1e
00000020 | 8e 4b b3 e1 d8 7c 5c 9e   ff 9d 22 31 46 de

TCM_LoadKey success

-------> begin TCM_Owner_APTerminate
sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 70 0b 37 f2 6a 9d
00000010 | 24 65 2c 4a e0 1e 43 1d   12 db f0 2a ed 0b 84 02
00000020 | d5 65 89 da 2a fa 7c 51   08 43 44 85 bb 80

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

handle
00000000 | 39 17 26 44

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 01 39 17 26 44
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | 2a 3e 40 b9 c4 f3 b9 09   88 3e 2c 5e 47 f8 92 93
00000040 | 8b e8 f0 2e 1b 4c c6 32   b3 dc b7 25 5f 90 91 bb

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 10 68 63 4d 6f 0f
00000010 | 28 5c d5 e8 7a 8b 22 45   c8 67 6b 8a 5e a1 0f ae
00000020 | 05 97 eb 74 f5 81 c7 22   dd 5a 6f 39 0f 0f 6a 74
00000030 | 96 7b 55 eb 40 ca 6c bb   36 22 f9 28 d9 00 e4 8d
00000040 | 03 85 b7 cb f6 d7 e6 68   b8 bb 15 9e f8 a3 92 b3
00000050 | b2 48

Command TCM_Owner_APCreate success
sm3 data
00000000 | 00 00 80 c5 3e b9 c7 de   d4 31 cc 5d c7 de d4 30
00000010 | cc 5d b0 2a 00 00 00 24   fe b9 c7 de d4 30 cc 5d
00000020 | b0 29 25 51 f6 bb 4e be   c7 de d4 30 cc 5d b0 29
00000030 | 3e b9 c7 de d4 30 25 51   5a 60 33 44

SM3_soft result
00000000 | 03 13 4a ef 52 d7 18 42   b1 ff 7b a1 e8 9a c8 b1
00000010 | bf dd a3 6a d2 19 8b 53   f7 9d 18 7a 7c ee 54 a0

input data:
00000000 | 00 c2 00 00 00 6a 00 00   80 c5 39 17 26 44 3e b9
00000010 | c7 de d4 31 cc 5d c7 de   d4 30 cc 5d b0 2a 00 00
00000020 | 00 24 fe b9 c7 de d4 30   cc 5d b0 29 25 51 f6 bb
00000030 | 4e be c7 de d4 30 cc 5d   b0 29 3e b9 c7 de d4 30
00000040 | 25 51 5a 60 33 44 10 68   63 4d 0e b4 59 5f fd 61
00000050 | 1b 8c 8f 16 eb 6f b4 65   68 16 01 82 41 d1 96 b6
00000060 | 8d 6b 2b 24 18 89 02 62   6c 21

output data:
00000000 | 00 c5 00 00 00 5e 00 00   00 00 00 00 00 30 64 74
00000010 | df 20 d2 f5 ac f2 25 56   18 09 29 11 6b a4 b1 94
00000020 | 9e 87 2c 59 bd 83 4c e6   d1 84 e5 e4 07 eb c9 82
00000030 | 98 e0 fa 74 48 7a 1d 52   72 53 81 37 df 0e 95 ac
00000040 | 97 97 f3 62 18 f2 c0 c4   12 22 05 10 ec 81 aa 62
00000050 | 79 e9 0d 52 0e 14 9c 93   0c b0 ba bd 06 c4

TCM_SM4Encrypt success

-------> begin TCM_Owner_APTerminate
sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 10 68 63 4d 3e 40
00000010 | 6b f4 97 f3 9d a1 cd b7   b0 f4 60 7a bf 03 68 fa
00000020 | 8a 9b ee fd af f8 84 75   b2 99 da 4f ad 1d

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

enc_data
00000000 | 64 74 df 20 d2 f5 ac f2   25 56 18 09 29 11 6b a4
00000010 | b1 94 9e 87 2c 59 bd 83   4c e6 d1 84 e5 e4 07 eb
00000020 | c9 82 98 e0 fa 74 48 7a   1d 52 72 53 81 37 df 0e

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 01 39 17 26 44
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | 2a 3e 40 b9 c4 f3 b9 09   88 3e 2c 5e 47 f8 92 93
00000040 | 8b e8 f0 2e 1b 4c c6 32   b3 dc b7 25 5f 90 91 bb

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 13 2b 31 b5 6c cc
00000010 | d1 15 35 14 f1 a7 d1 f9   a7 6e 64 91 fa e4 26 56
00000020 | c5 98 16 c6 2e 86 02 b2   94 54 b6 58 84 2a 6b cb
00000030 | 6c 6a bc 7f 60 38 f4 db   49 bc 36 0d 42 1f 5a a6
00000040 | 19 41 be 84 b1 ec e5 db   b7 98 7b 20 ad 26 ab 9d
00000050 | 94 cc

Command TCM_Owner_APCreate success
sm3 data
00000000 | 00 00 80 c6 3e b9 c7 de   d4 31 cc 5d c7 de d4 30
00000010 | cc 5d b0 2a 00 00 00 30   64 74 df 20 d2 f5 ac f2
00000020 | 25 56 18 09 29 11 6b a4   b1 94 9e 87 2c 59 bd 83
00000030 | 4c e6 d1 84 e5 e4 07 eb   c9 82 98 e0 fa 74 48 7a
00000040 | 1d 52 72 53 81 37 df 0e

SM3_soft result
00000000 | 6c 77 e1 10 c0 c4 bf 60   2b 78 48 9c dc a2 94 13
00000010 | 46 68 a8 32 f1 06 ef 44   8d 19 aa 11 19 34 34 18

input data:
00000000 | 00 c2 00 00 00 76 00 00   80 c6 39 17 26 44 3e b9
00000010 | c7 de d4 31 cc 5d c7 de   d4 30 cc 5d b0 2a 00 00
00000020 | 00 30 64 74 df 20 d2 f5   ac f2 25 56 18 09 29 11
00000030 | 6b a4 b1 94 9e 87 2c 59   bd 83 4c e6 d1 84 e5 e4
00000040 | 07 eb c9 82 98 e0 fa 74   48 7a 1d 52 72 53 81 37
00000050 | df 0e 13 2b 31 b5 4d fc   e2 67 2a c9 aa ff 32 67
00000060 | 9f e9 6c 35 e6 d6 6e 33   f8 2b 86 6a 2c 18 ca 5a
00000070 | 63 8e f3 8e 58 55

output data:
00000000 | 00 c5 00 00 00 52 00 00   00 00 00 00 00 24 fe b9
00000010 | c7 de d4 30 cc 5d b0 29   25 51 f6 bb 4e be c7 de
00000020 | d4 30 cc 5d b0 29 3e b9   c7 de d4 30 25 51 5a 60
00000030 | 33 44 44 cb 56 2f 5f 41   f6 49 ca 0b a6 9a 92 f0
00000040 | 77 44 5b 40 18 38 02 b5   07 ee d9 71 7a 95 ce 75
00000050 | 72 34

TCM_SM4Decrypt success

-------> begin TCM_Owner_APTerminate
sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 13 2b 31 b5 98 cb
00000010 | d3 e2 bd ca 9b 43 60 56   ae 6f c7 6c 75 ec 6e 1b
00000020 | 1c bd 8d e1 fc cb fa 89   d5 7f b3 2e 6d f7

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

data
00000000 | fe b9 c7 de d4 30 cc 5d   b0 29 25 51 f6 bb 4e be
00000010 | c7 de d4 30 cc 5d b0 29   3e b9 c7 de d4 30 25 51
00000020 | 5a 60 33 44
```
### 3.2.10 SM2签名
```
# ./tcm_test /sm2sf zxcvbnm /dd

FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

sm3 data
00000000 | a8 c6 be 3d

SM3_soft result
00000000 | 16 47 b6 30 c5 84 2c 22   54 fd 14 23 64 7b 14 a9
00000010 | 2e e9 73 42 c5 c3 05 2b   5d ff 5b 6c b1 1f a8 a2

sm2_keyinfo
00000000 | 00 15 00 00 00 10 00 00   00 00 00 00 00 00 0b 00
00000010 | 04 00 05 00 00 00 04 00   00 01 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 01 40 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | e9 28 ee 4a 72 66 d3 a3   27 92 2e e0 84 72 ce 50
00000040 | b7 b6 8e c3 bc f5 9d e7   75 8b 7a dd 6a 9d 77 0a

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 54 e4 61 df b8 ea
00000010 | f4 a1 5c 6c 35 21 4f c9   87 c2 4f db c2 17 5d b8
00000020 | 5d 18 f7 ff 0f 6f 28 f3   77 22 2c 9e 20 86 ec 47
00000030 | fe e7 58 54 d4 dc 2f 88   43 89 0a 88 5c 71 59 0b
00000040 | 5a 8b fc 42 e2 ee e6 55   64 94 84 0d f6 ba 69 23
00000050 | 3e 23

Command TCM_Owner_APCreate success
seq_APCreateOut:
00000000 | ec 47 fe e7

sm3 data
00000000 | 96 ac 48 2c ae 4c d8 f8   5a c8 32 4d f2 06 e5 13
00000010 | c8 b0 4e e3 9b 44 21 36   8c 58 09 50 41 13 86 fd
00000020 | ec 47 fe e7

SM3_soft result
00000000 | fb 69 91 00 9b 57 73 4e   02 94 c5 70 72 15 ba 38
00000010 | 2f 89 14 c9 2f 48 19 4b   55 76 b1 5c 4b 35 3c 78

keyauth
00000000 | fb 69 91 00 9b 57 73 4e   02 94 c5 70 72 15 ba 38
00000010 | 2f 89 14 c9 2f 48 19 4b   55 76 b1 5c 4b 35 3c 78

calculate hash begin
sm3 data
00000000 | 00 00 80 1f fb 69 91 00   9b 57 73 4e 02 94 c5 70
00000010 | 72 15 ba 38 2f 89 14 c9   2f 48 19 4b 55 76 b1 5c
00000020 | 4b 35 3c 78 fb 69 91 00   9b 57 73 4e 02 94 c5 70
00000030 | 72 15 ba 38 2f 89 14 c9   2f 48 19 4b 55 76 b1 5c
00000040 | 4b 35 3c 78 00 15 00 00   00 10 00 00 00 00 00 00
00000050 | 00 00 0b 00 04 00 05 00   00 00 04 00 00 01 00 00
00000060 | 00 00 00 00 00 00 00 00   00 00 00

SM3_soft result
00000000 | 55 9b b3 f0 ca 6a bd c8   20 ed 10 e6 37 b2 99 d9
00000010 | 5c 68 62 0b db 20 a2 9b   64 14 1e b8 eb b8 eb 9e

inMac
00000000 | 29 9c 21 2e 73 b2 d8 be   4e ce 4c f1 62 24 79 30
00000010 | 73 30 cb 03 63 be 8f fa   4c 26 74 56 68 77 6e f8

input data:
00000000 | 00 c2 00 00 00 99 00 00   80 1f 40 00 00 00 fb 69
00000010 | 91 00 9b 57 73 4e 02 94   c5 70 72 15 ba 38 2f 89
00000020 | 14 c9 2f 48 19 4b 55 76   b1 5c 4b 35 3c 78 fb 69
00000030 | 91 00 9b 57 73 4e 02 94   c5 70 72 15 ba 38 2f 89
00000040 | 14 c9 2f 48 19 4b 55 76   b1 5c 4b 35 3c 78 00 15
00000050 | 00 00 00 10 00 00 00 00   00 00 00 00 0b 00 04 00
00000060 | 05 00 00 00 04 00 00 01   00 00 00 00 00 00 00 00
00000070 | 00 00 00 00 00 54 e4 61   df 29 9c 21 2e 73 b2 d8
00000080 | be 4e ce 4c f1 62 24 79   30 73 30 cb 03 63 be 8f
00000090 | fa 4c 26 74 56 68 77 6e   f8

output data:
00000000 | 00 c5 00 00 01 22 00 00   00 00 00 15 00 00 00 10
00000010 | 00 00 00 00 00 00 00 00   0b 00 04 00 05 00 00 00
00000020 | 04 00 00 01 00 00 00 00   00 00 00 00 41 04 b5 65
00000030 | f1 74 1a 9d 6e 3d 15 37   46 18 cf a7 b9 1c 56 09
00000040 | 9e e3 df e0 f7 8e 2d 19   86 3f 2b b4 72 d8 73 72
00000050 | 4e 6a 3e 2d de 9c ab 7b   92 b2 7b 87 d7 40 0a 19
00000060 | c3 06 60 6f ef 3d 56 09   81 8f 11 20 59 3e 00 00
00000070 | 00 90 77 6d 94 d9 5e d1   ef d9 c5 af 6f ae dd 35
00000080 | 01 83 65 b8 ea 18 88 62   74 8e 02 8a 38 00 26 fe
00000090 | 87 fc 83 87 c7 37 09 54   12 b3 17 95 0c ba 32 52
000000a0 | 57 14 6e 3a 26 ca cf d4   0b 16 2a 73 7f e1 18 da
000000b0 | b5 7e 97 71 be 21 36 b2   23 fc e4 ec f0 d7 00 63
000000c0 | ba a2 8c da 25 01 57 38   c0 e3 86 5a 3f d8 0f 1a
000000d0 | 7f a8 24 96 fb 52 4c 3f   7d 52 7e 6e 6e 26 a8 07
000000e0 | f4 e7 43 9e 58 20 36 6c   70 e5 71 40 97 0b ae 01
000000f0 | aa 6e 5c 0b f6 9f 9c 15   05 bb 47 fd a1 64 17 fd
00000100 | 97 85 f4 6e 27 d2 b4 4d   69 7f de 09 3a a4 9c 69
00000110 | ae 23 d3 db fd 57 39 20   73 0c b3 78 59 f0 47 27
00000120 | 5f e2

TCM_CreateWrapKey success

-------> begin TCM_Owner_APTerminate
sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 54 e4 61 df b9 fb
00000010 | b7 e6 d8 5b 66 ca 42 ee   f6 0f af 07 c0 e2 f7 16
00000020 | e0 da b2 5e 6d 45 71 f0   c5 e9 3a 95 f4 76

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 04 40 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | e9 28 ee 4a 72 66 d3 a3   27 92 2e e0 84 72 ce 50
00000040 | b7 b6 8e c3 bc f5 9d e7   75 8b 7a dd 6a 9d 77 0a

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 2f fa 8c f0 15 19
00000010 | a7 1d 44 44 9a 27 d6 13   12 50 f5 cf 90 9d b3 f7
00000020 | 4a 99 98 82 b8 6b 0d 8f   d4 00 e0 5e 20 6c 33 58
00000030 | df 1f 27 cc 5c 7f 7c 87   c5 d6 3f 37 72 7a 53 09
00000040 | 14 ab 96 a8 08 ba c0 1e   c2 05 16 0e 17 0c 14 50
00000050 | 5a c2

Command TCM_Owner_APCreate success

sm3 data
00000000 | 00 00 80 ef 00 15 00 00   00 10 00 00 00 00 00 00
00000010 | 00 00 0b 00 04 00 05 00   00 00 04 00 00 01 00 00
00000020 | 00 00 00 00 00 00 41 04   b5 65 f1 74 1a 9d 6e 3d
00000030 | 15 37 46 18 cf a7 b9 1c   56 09 9e e3 df e0 f7 8e
00000040 | 2d 19 86 3f 2b b4 72 d8   73 72 4e 6a 3e 2d de 9c
00000050 | ab 7b 92 b2 7b 87 d7 40   0a 19 c3 06 60 6f ef 3d
00000060 | 56 09 81 8f 11 20 59 3e   00 00 00 90 77 6d 94 d9
00000070 | 5e d1 ef d9 c5 af 6f ae   dd 35 01 83 65 b8 ea 18
00000080 | 88 62 74 8e 02 8a 38 00   26 fe 87 fc 83 87 c7 37
00000090 | 09 54 12 b3 17 95 0c ba   32 52 57 14 6e 3a 26 ca
000000a0 | cf d4 0b 16 2a 73 7f e1   18 da b5 7e 97 71 be 21
000000b0 | 36 b2 23 fc e4 ec f0 d7   00 63 ba a2 8c da 25 01
000000c0 | 57 38 c0 e3 86 5a 3f d8   0f 1a 7f a8 24 96 fb 52
000000d0 | 4c 3f 7d 52 7e 6e 6e 26   a8 07 f4 e7 43 9e 58 20
000000e0 | 36 6c 70 e5 71 40 97 0b   ae 01 aa 6e 5c 0b f6 9f
000000f0 | 9c 15 05 bb 47 fd a1 64   17 fd 97 85

SM3_soft result
00000000 | d2 3e 70 e6 fe cc 6e ad   20 7c 09 51 cc 16 27 4b
00000010 | 3b 7e f8 e0 0b c7 82 49   2e c8 4c 4c 37 49 86 96

inMac
00000000 | ad 3b e2 d7 03 73 a0 a3   cc 34 53 28 cc 44 22 74
00000010 | 13 52 f5 bd 33 b9 45 61   99 72 19 5b 0a 2e 17 78

input data:
00000000 | 00 c2 00 00 01 2a 00 00   80 ef 40 00 00 00 00 15
00000010 | 00 00 00 10 00 00 00 00   00 00 00 00 0b 00 04 00
00000020 | 05 00 00 00 04 00 00 01   00 00 00 00 00 00 00 00
00000030 | 41 04 b5 65 f1 74 1a 9d   6e 3d 15 37 46 18 cf a7
00000040 | b9 1c 56 09 9e e3 df e0   f7 8e 2d 19 86 3f 2b b4
00000050 | 72 d8 73 72 4e 6a 3e 2d   de 9c ab 7b 92 b2 7b 87
00000060 | d7 40 0a 19 c3 06 60 6f   ef 3d 56 09 81 8f 11 20
00000070 | 59 3e 00 00 00 90 77 6d   94 d9 5e d1 ef d9 c5 af
00000080 | 6f ae dd 35 01 83 65 b8   ea 18 88 62 74 8e 02 8a
00000090 | 38 00 26 fe 87 fc 83 87   c7 37 09 54 12 b3 17 95
000000a0 | 0c ba 32 52 57 14 6e 3a   26 ca cf d4 0b 16 2a 73
000000b0 | 7f e1 18 da b5 7e 97 71   be 21 36 b2 23 fc e4 ec
000000c0 | f0 d7 00 63 ba a2 8c da   25 01 57 38 c0 e3 86 5a
000000d0 | 3f d8 0f 1a 7f a8 24 96   fb 52 4c 3f 7d 52 7e 6e
000000e0 | 6e 26 a8 07 f4 e7 43 9e   58 20 36 6c 70 e5 71 40
000000f0 | 97 0b ae 01 aa 6e 5c 0b   f6 9f 9c 15 05 bb 47 fd
00000100 | a1 64 17 fd 97 85 2f fa   8c f0 ad 3b e2 d7 03 73
00000110 | a0 a3 cc 34 53 28 cc 44   22 74 13 52 f5 bd 33 b9
00000120 | 45 61 99 72 19 5b 0a 2e   17 78

output data:
00000000 | 00 c5 00 00 00 2e 00 00   00 00 9a e9 ff a2 d2 4a
00000010 | 8d 22 ae 7f 29 d8 0a 7d   dd 8f c6 f6 e5 15 b7 de
00000020 | 3c 72 5a bc 09 92 6a 2a   2a cf 19 04 6d 51

TCM_LoadKey success

-------> begin TCM_Owner_APTerminate
sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 2f fa 8c f0 c7 8e
00000010 | 0e f7 f9 47 9e 3a 59 92   2c ab 9e e4 d0 38 ea 4c
00000020 | ca d0 9c 6d 25 90 66 04   31 76 e2 9e ee 21

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 01 9a e9 ff a2
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | 2a 3e 40 b9 c4 f3 b9 09   88 3e 2c 5e 47 f8 92 93
00000040 | 8b e8 f0 2e 1b 4c c6 32   b3 dc b7 25 5f 90 91 bb

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 e4 b2 24 92 8e 4a
00000010 | 44 a9 3d ce 6c 74 b4 f5   52 95 86 36 f3 32 d5 bf
00000020 | ab 34 49 1d ad 38 9e 51   04 b8 4a 7f 3d 0c 22 ea
00000030 | 41 04 2d d8 5b 9c e2 41   2b 9e 57 b4 42 65 77 06
00000040 | 57 48 7d 66 e6 cf 03 89   9b 08 36 9d ce 69 a9 e6
00000050 | a8 f1

Command TCM_Owner_APCreate success
sm3 data
00000000 | 00 00 80 3c 00 00 00 20   fe b9 c7 de d4 30 cc 5d
00000010 | b0 29 25 51 f6 bb 4e be   c7 de d4 30 cc 5d b0 29
00000020 | 3e b9 c7 de d4 30 25 51

SM3_soft result
00000000 | 39 c0 75 10 20 60 50 42   48 91 d3 16 c9 64 54 3c
00000010 | cc a7 1a e0 01 40 f4 2d   f6 49 3d 0d cc 54 a3 83

input data:
00000000 | 00 c2 00 00 00 56 00 00   80 3c 9a e9 ff a2 00 00
00000010 | 00 20 fe b9 c7 de d4 30   cc 5d b0 29 25 51 f6 bb
00000020 | 4e be c7 de d4 30 cc 5d   b0 29 3e b9 c7 de d4 30
00000030 | 25 51 e4 b2 24 92 b7 e7   a6 e8 30 55 90 a8 3d a6
00000040 | a1 52 ad e1 e5 fd 44 90   fe 85 d4 b3 1f f6 77 a0
00000050 | 16 63 80 40 90 de

output data:
00000000 | 00 c5 00 00 00 6e 00 00   00 00 00 00 00 40 41 b5
00000010 | dd c2 22 8b b0 4c fc 45   0d 4a 67 27 95 5d 77 40
00000020 | a2 3d 70 dc cf 5d ef bc   23 b4 f4 3b 5f 8d c5 bf
00000030 | 49 88 f6 8f 1a ed 25 8f   85 9d 33 c2 74 43 30 71
00000040 | 01 b8 74 ec ed 7c 37 6f   9a f0 08 d9 a3 3f 58 82
00000050 | 08 8b 18 03 5a 31 f8 45   39 8f 97 66 b4 df d5 34
00000060 | 7c 85 37 f3 cc f7 ba 8e   ae e4 cf 5a ba fa

TCM_Sign success

-------> begin TCM_Owner_APTerminate
sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 e4 b2 24 92 9b 6f
00000010 | 67 d9 43 92 91 89 c2 83   54 9e d6 40 0d 55 ff c9
00000020 | 4b 1c b9 a2 80 2d 9c 06   61 c4 a5 cf 7f 98

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

TCM_Sign success
```
### 3.2.11 定义NV空间
```
# ./tcm_test /tpcm password /nvdef /dd

FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

sm3 data
00000000 | 0a 33 7f 2d

SM3_soft result
00000000 | 76 6c 73 7b d9 39 8d 67   41 5e ed 68 35 e4 e1 7c
00000010 | dd e1 d1 8d 70 84 58 0d   a9 1f 1f 8b 57 9d a7 00

TCM_NV_PER_OWNER_READ | TCM_NV_PER_OWNERWRITE
00000000 | 00 02 00 02

input data:
00000000 | 00 c1 00 00 00 0e 00 00   80 15 00 00 00 08

output data:
00000000 | 00 c4 00 00 00 2a 00 00   00 00 00 00 00 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00

sm3 data
00000000 | 00 02 00 01 00 00 00 20   00 00 00 00 00 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00

SM3_soft result
00000000 | 33 30 da 17 4c 3b ed 14   83 58 49 90 54 c0 fd 8f
00000010 | 39 db e4 fc a4 aa 24 04   8e 3a 8a 43 e9 68 95 a0

input data:
00000000 | 00 c1 00 00 00 0e 00 00   80 46 00 00 00 20

output data:
00000000 | 00 c4 00 00 00 2e 00 00   00 00 00 00 00 20 13 e7
00000010 | b8 15 3c 7f eb a6 68 90   dd a0 50 c2 c5 31 9a 2b
00000020 | 4c f1 e3 98 8a f5 1a b5   dc 85 1a a0 ae ec

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 02 00 00 00 00
00000010 | 13 e7 b8 15 3c 7f eb a6   68 90 dd a0 50 c2 c5 31
00000020 | 9a 2b 4c f1 e3 98 8a f5   1a b5 dc 85 1a a0 ae ec
00000030 | 79 33 b9 7d 66 4a 31 b6   18 98 3d 46 7b 5c 26 1f
00000040 | 31 9a b7 03 b2 8d 5f 47   3e 30 47 aa af 28 1c 01

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 15 b5 01 3a 50 29
00000010 | b7 ae c4 ed 5b 7d 54 d4   ca 52 0d aa 1d 61 37 0e
00000020 | af 51 fd 24 b0 9a e9 d3   c9 cb 70 99 b7 32 40 2c
00000030 | c6 13 7b c7 9b 62 01 d8   ba 2a 43 0d 5d 87 58 29
00000040 | 13 4d d9 63 15 f4 c7 09   d3 49 95 53 fe e4 70 f5
00000050 | 56 84

input data:
00000000 | 00 c1 00 00 00 0a 00 00   80 ea

output data:
00000000 | 00 c4 00 00 00 0e 00 00   00 00 00 00 04 00

input data:
00000000 | 00 c1 00 00 00 2e 00 00   80 eb 00 00 00 20 31 e6
00000010 | b2 52 86 ab b0 38 31 aa   29 a1 25 6d 54 96 31 f2
00000020 | 3e d8 a1 86 5a ab c5 7d   c1 90 20 66 76 33

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 12 00 00   80 ec 00 00 00 04 40 2c
00000010 | c6 13

output data:
00000000 | 00 c4 00 00 00 2a 00 00   00 00 0d f5 1c 44 3f 3b
00000010 | be 35 7f 88 c3 f8 a0 9f   05 aa 9f 2a 23 28 6f d4
00000020 | 37 e0 7a 7e 63 ee 08 ed   cc 3d

input data:
00000000 | 00 c1 00 00 00 0a 00 00   80 ea

output data:
00000000 | 00 c4 00 00 00 0e 00 00   00 00 00 00 04 00

input data:
00000000 | 00 c1 00 00 00 12 00 00   80 eb 00 00 00 04 00 00
00000010 | 80 cc

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 b9 00 00   80 eb 00 00 00 ab 00 18
00000010 | 40 00 00 a0 00 06 01 01   00 02 00 01 00 02 00 01
00000020 | 33 30 da 17 4c 3b ed 14   83 58 49 90 54 c0 fd 8f
00000030 | 39 db e4 fc a4 aa 24 04   8e 3a 8a 43 e9 68 95 a0
00000040 | 33 30 da 17 4c 3b ed 14   83 58 49 90 54 c0 fd 8f
00000050 | 39 db e4 fc a4 aa 24 04   8e 3a 8a 43 e9 68 95 a0
00000060 | 00 06 01 01 00 02 00 01   00 02 00 01 33 30 da 17
00000070 | 4c 3b ed 14 83 58 49 90   54 c0 fd 8f 39 db e4 fc
00000080 | a4 aa 24 04 8e 3a 8a 43   e9 68 95 a0 33 30 da 17
00000090 | 4c 3b ed 14 83 58 49 90   54 c0 fd 8f 39 db e4 fc
000000a0 | a4 aa 24 04 8e 3a 8a 43   e9 68 95 a0 00 17 00 02
000000b0 | 00 02 00 00 00 00 00 01   8c

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 2e 00 00   80 ec 00 00 00 20 0d f5
00000010 | 1c 44 3f 3b be 35 7f 88   c3 f8 a0 9f 05 aa 9f 2a
00000020 | 23 28 6f d4 37 e0 7a 7e   63 ee 08 ed cc 3d

output data:
00000000 | 00 c4 00 00 00 2a 00 00   00 00 ee c0 d4 be 86 27
00000010 | 0b 4a e7 d8 22 80 fb 50   37 cd f2 57 69 4e b5 59
00000020 | d1 be e6 fb c6 f1 d9 34   c5 b3

input data:
00000000 | 00 c2 00 00 00 f9 00 00   80 cc 00 18 40 00 00 a0
00000010 | 00 06 01 01 00 02 00 01   00 02 00 01 33 30 da 17
00000020 | 4c 3b ed 14 83 58 49 90   54 c0 fd 8f 39 db e4 fc
00000030 | a4 aa 24 04 8e 3a 8a 43   e9 68 95 a0 33 30 da 17
00000040 | 4c 3b ed 14 83 58 49 90   54 c0 fd 8f 39 db e4 fc
00000050 | a4 aa 24 04 8e 3a 8a 43   e9 68 95 a0 00 06 01 01
00000060 | 00 02 00 01 00 02 00 01   33 30 da 17 4c 3b ed 14
00000070 | 83 58 49 90 54 c0 fd 8f   39 db e4 fc a4 aa 24 04
00000080 | 8e 3a 8a 43 e9 68 95 a0   33 30 da 17 4c 3b ed 14
00000090 | 83 58 49 90 54 c0 fd 8f   39 db e4 fc a4 aa 24 04
000000a0 | 8e 3a 8a 43 e9 68 95 a0   00 17 00 02 00 02 00 00
000000b0 | 00 00 00 01 8c 0d f5 1c   44 3f 3b be 35 7f 88 c3
000000c0 | f8 a0 9f 05 aa 9f 2a 23   28 6f d4 37 e0 7a 7e 63
000000d0 | ee 08 ed cc 3d 15 b5 01   3a c0 d5 7c 76 82 2d f1
000000e0 | f0 72 b9 54 a7 b9 64 f3   43 ee 58 63 89 60 21 df
000000f0 | ec 95 4d bb 42 8e 7b 16   0f

output data:
00000000 | 00 c5 00 00 00 2a 00 00   00 00 02 40 14 36 2e f1
00000010 | 43 de 84 32 b9 3c 39 4e   c2 f0 ea 9f 12 66 e4 af
00000020 | 27 18 eb e1 f0 90 29 a4   63 62

sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 15 b5 01 3a 38 0f
00000010 | 74 e1 79 7b 0a 03 57 cb   62 ff 65 46 d0 8a d9 fc
00000020 | b4 a6 de 65 d5 25 27 2c   2d db 4c e7 73 1b

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

TCM_NV_DefineSpace Success(TCM_NV_INDEX_TPCM_1)
input data:
00000000 | 00 c1 00 00 00 0e 00 00   80 15 00 00 00 08

output data:
00000000 | 00 c4 00 00 00 2a 00 00   00 00 00 00 00 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00

sm3 data
00000000 | 00 02 00 01 00 00 00 20   00 00 00 00 00 00 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00

SM3_soft result
00000000 | 33 30 da 17 4c 3b ed 14   83 58 49 90 54 c0 fd 8f
00000010 | 39 db e4 fc a4 aa 24 04   8e 3a 8a 43 e9 68 95 a0

input data:
00000000 | 00 c1 00 00 00 0e 00 00   80 46 00 00 00 20

output data:
00000000 | 00 c4 00 00 00 2e 00 00   00 00 00 00 00 20 2e 50
00000010 | e3 39 93 5c 3c e5 bc 5f   79 49 4c 75 64 c7 1d 17
00000020 | 65 42 69 d6 0a 7e c2 c5   d3 bc fd 23 7f 95

input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 02 00 00 00 00
00000010 | 2e 50 e3 39 93 5c 3c e5   bc 5f 79 49 4c 75 64 c7
00000020 | 1d 17 65 42 69 d6 0a 7e   c2 c5 d3 bc fd 23 7f 95
00000030 | 43 30 18 ed d9 9c f4 4e   d6 4b 88 1b 60 94 aa 94
00000040 | 93 56 2b 9e ec 66 a0 92   22 6f f6 bf 00 65 0d b1

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 57 8e 34 6e 90 c1
00000010 | 28 86 06 55 22 85 e4 5c   f6 fd 8b b7 e6 a6 ed c8
00000020 | eb 0d 3a 97 d8 88 3f 30   8f dd a3 62 ca 82 fb c5
00000030 | 1a 22 91 d7 39 a6 e0 01   b6 b3 1d 32 6c 9a 72 8e
00000040 | 03 a5 b3 b7 0b 69 ae d3   05 69 b7 9d 8b e1 2f 28
00000050 | 62 fc

input data:
00000000 | 00 c1 00 00 00 0a 00 00   80 ea

output data:
00000000 | 00 c4 00 00 00 0e 00 00   00 00 00 00 04 00

input data:
00000000 | 00 c1 00 00 00 2e 00 00   80 eb 00 00 00 20 37 b0
00000010 | cd 58 24 bc e3 0b ce e7   ae 51 8a 7d f9 e3 95 b3
00000020 | 11 16 04 60 8b e0 5f df   94 51 b3 31 9b db

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 12 00 00   80 ec 00 00 00 04 fb c5
00000010 | 1a 22

output data:
00000000 | 00 c4 00 00 00 2a 00 00   00 00 f2 be bd 19 62 64
00000010 | 61 e0 75 63 43 10 b0 50   16 bb 01 1e d9 69 5f 25
00000020 | 64 75 54 9a b9 7e 83 2a   fd 7f

input data:
00000000 | 00 c1 00 00 00 0a 00 00   80 ea

output data:
00000000 | 00 c4 00 00 00 0e 00 00   00 00 00 00 04 00

input data:
00000000 | 00 c1 00 00 00 12 00 00   80 eb 00 00 00 04 00 00
00000010 | 80 cc

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 b9 00 00   80 eb 00 00 00 ab 00 18
00000010 | 40 00 00 a1 00 06 01 01   00 02 00 01 00 02 00 01
00000020 | 33 30 da 17 4c 3b ed 14   83 58 49 90 54 c0 fd 8f
00000030 | 39 db e4 fc a4 aa 24 04   8e 3a 8a 43 e9 68 95 a0
00000040 | 33 30 da 17 4c 3b ed 14   83 58 49 90 54 c0 fd 8f
00000050 | 39 db e4 fc a4 aa 24 04   8e 3a 8a 43 e9 68 95 a0
00000060 | 00 06 01 01 00 02 00 01   00 02 00 01 33 30 da 17
00000070 | 4c 3b ed 14 83 58 49 90   54 c0 fd 8f 39 db e4 fc
00000080 | a4 aa 24 04 8e 3a 8a 43   e9 68 95 a0 33 30 da 17
00000090 | 4c 3b ed 14 83 58 49 90   54 c0 fd 8f 39 db e4 fc
000000a0 | a4 aa 24 04 8e 3a 8a 43   e9 68 95 a0 00 17 00 02
000000b0 | 00 02 00 00 00 00 00 00   30

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

input data:
00000000 | 00 c1 00 00 00 2e 00 00   80 ec 00 00 00 20 f2 be
00000010 | bd 19 62 64 61 e0 75 63   43 10 b0 50 16 bb 01 1e
00000020 | d9 69 5f 25 64 75 54 9a   b9 7e 83 2a fd 7f

output data:
00000000 | 00 c4 00 00 00 2a 00 00   00 00 63 d5 b9 7a ea ba
00000010 | 61 5a 43 56 a1 75 b4 f7   84 58 d9 fe 74 b5 9f 0e
00000020 | 14 81 83 2b 79 66 c8 11   fe 37

input data:
00000000 | 00 c2 00 00 00 f9 00 00   80 cc 00 18 40 00 00 a1
00000010 | 00 06 01 01 00 02 00 01   00 02 00 01 33 30 da 17
00000020 | 4c 3b ed 14 83 58 49 90   54 c0 fd 8f 39 db e4 fc
00000030 | a4 aa 24 04 8e 3a 8a 43   e9 68 95 a0 33 30 da 17
00000040 | 4c 3b ed 14 83 58 49 90   54 c0 fd 8f 39 db e4 fc
00000050 | a4 aa 24 04 8e 3a 8a 43   e9 68 95 a0 00 06 01 01
00000060 | 00 02 00 01 00 02 00 01   33 30 da 17 4c 3b ed 14
00000070 | 83 58 49 90 54 c0 fd 8f   39 db e4 fc a4 aa 24 04
00000080 | 8e 3a 8a 43 e9 68 95 a0   33 30 da 17 4c 3b ed 14
00000090 | 83 58 49 90 54 c0 fd 8f   39 db e4 fc a4 aa 24 04
000000a0 | 8e 3a 8a 43 e9 68 95 a0   00 17 00 02 00 02 00 00
000000b0 | 00 00 00 00 30 f2 be bd   19 62 64 61 e0 75 63 43
000000c0 | 10 b0 50 16 bb 01 1e d9   69 5f 25 64 75 54 9a b9
000000d0 | 7e 83 2a fd 7f 57 8e 34   6e d1 5a 5f ba a4 73 b4
000000e0 | 2b 7f 93 9a 48 73 b3 1e   dd a1 98 ce 0e f9 b6 76
000000f0 | ce 6e b8 0b 89 b7 da bb   1d

output data:
00000000 | 00 c5 00 00 00 2a 00 00   00 00 ff b8 8b 01 44 0b
00000010 | ef 17 3e 35 8a fc 6a 7e   c5 50 0e e3 22 95 8e 13
00000020 | c3 a3 e0 47 9b 39 64 c5   9c f7

sm3 data
00000000 | 00 00 80 c0

SM3_soft result
00000000 | 6c 3f 8b 9a f1 b0 9c 1a   30 cc 02 4c a4 e9 a9 40
00000010 | a2 0d 23 c2 c0 68 d6 d5   1e 80 1e de 35 13 c1 53

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 57 8e 34 6e 38 fc
00000010 | 85 31 ed f5 4e 44 8b 82   df dd e9 d4 af ce aa 47
00000020 | 01 d5 0b 56 4e a2 d3 d5   26 80 87 24 68 f4

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

TCM_NV_DefineSpace Success(TCM_NV_INDEX_TPCM_2)
```
### 3.2.12 写数据到NV
```
# ./tcm_test /tpcm 1234567890abcdef1234567890abcdef /nvw goon.bin /dd

FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

b:
00000000 | 12 34 56 78 90 ab cd ef   12 34 56 78 90 ab cd ef

hash:
00000000 | 27 1f b6 70 63 53 dc 06   0a be ce a9 54 8e 7a 47
00000010 | 84 32 3f 12 68 e9 fd 7d   e5 1c 05 de 2d 05 16 7d

binData:
00000000 | 01 00 00 00 01 00 00 00   00 00 00 00 00 00 10 00
00000010 | 20 00 3b 17 1c 23 90 0b   7c a7 9b a2 a0 67 00 9e
00000020 | ca 25 b8 2a 8f 6a 88 89   54 06 bd 1d 3e 43 b6 72
00000030 | 43 d6 ff ff 12 00 01 ff   00 00 00 00 00 00 00 00
00000040 | 20 00 ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000050 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000060 | ff ff ff ff 12 00 00 ff   00 00 00 00 00 00 00 00
00000070 | 20 00 ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000080 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000090 | ff ff ff ff 12 00 00 ff   00 00 00 00 00 00 00 00
000000a0 | 20 00 ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000b0 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000c0 | ff ff ff ff 12 00 00 ff   00 00 00 00 00 00 00 00
000000d0 | 00 00 00 00 20 00 ff ff   ff ff ff ff ff ff ff ff
000000e0 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000f0 | ff ff ff ff ff ff ff ff   12 00 00 ff 00 00 00 00
00000100 | 00 00 00 00 20 00 ff ff   ff ff ff ff ff ff ff ff
00000110 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000120 | ff ff ff ff ff ff ff ff   12 00 00 ff 00 00 00 00
00000130 | 00 00 00 00 20 00 ff ff   ff ff ff ff ff ff ff ff
00000140 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000150 | ff ff ff ff ff ff ff ff   12 00 00 ff 00 00 00 00
00000160 | 00 00 00 00 20 00 ff ff   ff ff ff ff ff ff ff ff
00000170 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000180 | ff ff ff ff ff ff ff ff   12 00 00 ff

input data:
00000000 | 00 c1 00 00 00 0e 00 00   80 46 00 00 00 20

output data:
00000000 | 00 c4 00 00 00 2e 00 00   00 00 00 00 00 20 d8 15
00000010 | a2 c3 97 63 6e 87 4b 18   3f ad aa 3a 09 1d da 8c
00000020 | 8a d8 22 36 80 5b 3f ee   b5 35 30 45 92 39

TCM_GetRandom Success
input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 02 00 00 00 00
00000010 | d8 15 a2 c3 97 63 6e 87   4b 18 3f ad aa 3a 09 1d
00000020 | da 8c 8a d8 22 36 80 5b   3f ee b5 35 30 45 92 39
00000030 | c9 5d 81 a8 35 99 2d fd   38 cd d5 6a 2b c5 4b 58
00000040 | d1 07 f7 76 88 46 34 fd   91 a6 00 22 0d 7e f5 7a

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 72 75 47 cf b4 cd
00000010 | e8 9d 3a b7 8d 41 54 bd   d7 c0 45 0a 3e 65 87 e8
00000020 | fd b5 02 ac dd 4a ef 97   9a b8 34 9e b7 d1 90 1b
00000030 | ad 46 47 a3 0e 2d c3 16   79 8f d3 4b 85 9a 58 c4
00000040 | 42 33 2e 58 5b 31 11 19   e8 77 90 7a 35 e3 df 53
00000050 | 60 be

APCreate Success
sm3 data
00000000 | 00 00 80 cd 40 00 00 a0   00 00 00 00 00 00 01 8c
00000010 | 01 00 00 00 01 00 00 00   00 00 00 00 00 00 10 00
00000020 | 20 00 3b 17 1c 23 90 0b   7c a7 9b a2 a0 67 00 9e
00000030 | ca 25 b8 2a 8f 6a 88 89   54 06 bd 1d 3e 43 b6 72
00000040 | 43 d6 ff ff 12 00 01 ff   00 00 00 00 00 00 00 00
00000050 | 20 00 ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000060 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000070 | ff ff ff ff 12 00 00 ff   00 00 00 00 00 00 00 00
00000080 | 20 00 ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000090 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000a0 | ff ff ff ff 12 00 00 ff   00 00 00 00 00 00 00 00
000000b0 | 20 00 ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000c0 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000d0 | ff ff ff ff 12 00 00 ff   00 00 00 00 00 00 00 00
000000e0 | 00 00 00 00 20 00 ff ff   ff ff ff ff ff ff ff ff
000000f0 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000100 | ff ff ff ff ff ff ff ff   12 00 00 ff 00 00 00 00
00000110 | 00 00 00 00 20 00 ff ff   ff ff ff ff ff ff ff ff
00000120 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000130 | ff ff ff ff ff ff ff ff   12 00 00 ff 00 00 00 00
00000140 | 00 00 00 00 20 00 ff ff   ff ff ff ff ff ff ff ff
00000150 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000160 | ff ff ff ff ff ff ff ff   12 00 00 ff 00 00 00 00
00000170 | 00 00 00 00 20 00 ff ff   ff ff ff ff ff ff ff ff
00000180 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000190 | ff ff ff ff ff ff ff ff   12 00 00 ff

SM3_soft result
00000000 | 45 8e f7 ce f6 3a 73 1f   03 a8 a0 7c 0c 3f c1 da
00000010 | f9 de 37 d7 f2 7f 42 7d   af 7e 4c 8e 42 ca ef 78

hash_Result:
00000000 | 45 8e f7 ce f6 3a 73 1f   03 a8 a0 7c 0c 3f c1 da
00000010 | f9 de 37 d7 f2 7f 42 7d   af 7e 4c 8e 42 ca ef 78

input data:
00000000 | 00 c2 00 00 01 c6 00 00   80 cd 40 00 00 a0 00 00
00000010 | 00 00 00 00 01 8c 01 00   00 00 01 00 00 00 00 00
00000020 | 00 00 00 00 10 00 20 00   3b 17 1c 23 90 0b 7c a7
00000030 | 9b a2 a0 67 00 9e ca 25   b8 2a 8f 6a 88 89 54 06
00000040 | bd 1d 3e 43 b6 72 43 d6   ff ff 12 00 01 ff 00 00
00000050 | 00 00 00 00 00 00 20 00   ff ff ff ff ff ff ff ff
00000060 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000070 | ff ff ff ff ff ff ff ff   ff ff 12 00 00 ff 00 00
00000080 | 00 00 00 00 00 00 20 00   ff ff ff ff ff ff ff ff
00000090 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000a0 | ff ff ff ff ff ff ff ff   ff ff 12 00 00 ff 00 00
000000b0 | 00 00 00 00 00 00 20 00   ff ff ff ff ff ff ff ff
000000c0 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000d0 | ff ff ff ff ff ff ff ff   ff ff 12 00 00 ff 00 00
000000e0 | 00 00 00 00 00 00 00 00   00 00 20 00 ff ff ff ff
000000f0 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000100 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff 12 00
00000110 | 00 ff 00 00 00 00 00 00   00 00 20 00 ff ff ff ff
00000120 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000130 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff 12 00
00000140 | 00 ff 00 00 00 00 00 00   00 00 20 00 ff ff ff ff
00000150 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000160 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff 12 00
00000170 | 00 ff 00 00 00 00 00 00   00 00 20 00 ff ff ff ff
00000180 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000190 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff 12 00
000001a0 | 00 ff 72 75 47 cf 94 35   17 67 fa 09 ee 28 62 4b
000001b0 | d5 5d 55 f5 c3 da cb 46   f0 f5 a7 a5 74 a2 d1 a7
000001c0 | 45 70 e7 ad ab cb

output data:
00000000 | 00 c5 00 00 00 2a 00 00   00 00 9a 05 5f 6b f1 4f
00000010 | 4b a2 cd 2e 40 ff a4 48   88 1e d7 1d 07 f1 b0 e1
00000020 | 0b 23 b8 42 77 a5 88 5a   f5 b0

TCM_NV_WriteValue success
input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 72 75 47 cf d3 d0
00000010 | d4 99 8d fb f9 17 fe e7   f9 ba 5e a7 92 c4 d9 71
00000020 | 04 72 49 d5 00 58 1e a5   ec be 71 98 d0 28

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

TCM_APTerminate success
APTerminate Success!
NV WriteValue Success
TCM_NV_WriteValue Success
```
### 3.2.13 从NV中读数据
```
# ./tcm_test /tpcm 1234567890abcdef1234567890abcdef /nvr /dd
FtdiSpiInit, Connected to device vid:did:rid of 1b4e: 0601: 17
SPI init Success

b:
00000000 | 12 34 56 78 90 ab cd ef   12 34 56 78 90 ab cd ef

hash:
00000000 | 27 1f b6 70 63 53 dc 06   0a be ce a9 54 8e 7a 47
00000010 | 84 32 3f 12 68 e9 fd 7d   e5 1c 05 de 2d 05 16 7d

input data:
00000000 | 00 c1 00 00 00 0e 00 00   80 46 00 00 00 20

output data:
00000000 | 00 c4 00 00 00 2e 00 00   00 00 00 00 00 20 63 f9
00000010 | 3e 42 1d 10 dc b8 1c 80   40 7f 2c 86 20 18 86 3f
00000020 | d5 f7 8d b6 81 f1 20 6d   3a 91 28 4b 23 8d

TCM_GetRandom Success
input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 02 00 00 00 00
00000010 | 63 f9 3e 42 1d 10 dc b8   1c 80 40 7f 2c 86 20 18
00000020 | 86 3f d5 f7 8d b6 81 f1   20 6d 3a 91 28 4b 23 8d
00000030 | 47 3a 74 28 0d 52 15 32   5a 22 b9 75 2e 7b 64 4b
00000040 | ee 16 cb 4e 2b 9a 5a 2e   cd b1 0d 53 17 65 87 e3

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 b4 08 b0 af 9e da
00000010 | 4a 93 35 64 b2 3d e5 ef   00 1f 9b af 0f bc 9b 2e
00000020 | 18 99 27 83 c8 56 e3 1c   03 4e bf ec 4d d2 6b ba
00000030 | ae 18 fd bc da 0a 7b 25   d5 b2 49 81 82 32 54 1e
00000040 | 0c ba 57 80 3c 38 12 b8   e4 ce 86 d8 75 53 82 29
00000050 | 1f 18

APCreate Success
TCM_APCreate Success

sm3 data
00000000 | 00 00 80 cf 40 00 00 a0   00 00 00 00 00 00 01 8c

SM3_soft result
00000000 | 16 9a cf 14 da 8f 5d ef   4b 85 12 95 25 59 ec a9
00000010 | 2e 44 ed cc 1b 2b 60 74   5e d9 69 19 af 8b 9b 88

hash_Result
00000000 | 16 9a cf 14 da 8f 5d ef   4b 85 12 95 25 59 ec a9
00000010 | 2e 44 ed cc 1b 2b 60 74   5e d9 69 19 af 8b 9b 88

input data:
00000000 | 00 c2 00 00 00 3a 00 00   80 cf 40 00 00 a0 00 00
00000010 | 00 00 00 00 01 8c b4 08   b0 af 30 90 5b 92 7f 69
00000020 | 8b 84 f7 b4 84 39 fd 4d   b5 c1 4f 28 37 e5 ff 51
00000030 | 74 3c 0b 1b 49 5a c5 1c   1a fe

output data:
00000000 | 00 c5 00 00 01 ba 00 00   00 00 00 00 01 8c 01 00
00000010 | 00 00 01 00 00 00 00 00   00 00 00 00 10 00 20 00
00000020 | 3b 17 1c 23 90 0b 7c a7   9b a2 a0 67 00 9e ca 25
00000030 | b8 2a 8f 6a 88 89 54 06   bd 1d 3e 43 b6 72 43 d6
00000040 | ff ff 12 00 01 ff 00 00   00 00 00 00 00 00 20 00
00000050 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000060 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000070 | ff ff 12 00 00 ff 00 00   00 00 00 00 00 00 20 00
00000080 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000090 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000a0 | ff ff 12 00 00 ff 00 00   00 00 00 00 00 00 20 00
000000b0 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000c0 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000d0 | ff ff 12 00 00 ff 00 00   00 00 00 00 00 00 00 00
000000e0 | 00 00 20 00 ff ff ff ff   ff ff ff ff ff ff ff ff
000000f0 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000100 | ff ff ff ff ff ff 12 00   00 ff 00 00 00 00 00 00
00000110 | 00 00 20 00 ff ff ff ff   ff ff ff ff ff ff ff ff
00000120 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000130 | ff ff ff ff ff ff 12 00   00 ff 00 00 00 00 00 00
00000140 | 00 00 20 00 ff ff ff ff   ff ff ff ff ff ff ff ff
00000150 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000160 | ff ff ff ff ff ff 12 00   00 ff 00 00 00 00 00 00
00000170 | 00 00 20 00 ff ff ff ff   ff ff ff ff ff ff ff ff
00000180 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000190 | ff ff ff ff ff ff 12 00   00 ff 53 15 63 19 3c a4
000001a0 | ed b4 86 cf e0 68 cf 90   68 24 93 dd 75 e2 1b 05
000001b0 | 20 26 21 b0 6c be 93 2c   b5 5c

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 b4 08 b0 af 83 1d
00000010 | 64 49 ff b3 84 3f 9a e5   59 25 93 6c 24 cd e3 40
00000020 | 1c cc 02 96 f0 8a 8e e8   7b 7f 4d 18 05 a4

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

fu_TCM_APTerminate success
APTerminate Success
TCM_NV_ReadValue(TCM_NV_INDEX_TPCM_1) Success

binData read:
读取nv内容成功，以下为内容信息，与写入的bin文件内容相比较，是一致的
00000000 | 01 00 00 00 01 00 00 00   00 00 00 00 00 00 10 00
00000010 | 20 00 3b 17 1c 23 90 0b   7c a7 9b a2 a0 67 00 9e
00000020 | ca 25 b8 2a 8f 6a 88 89   54 06 bd 1d 3e 43 b6 72
00000030 | 43 d6 ff ff 12 00 01 ff   00 00 00 00 00 00 00 00
00000040 | 20 00 ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000050 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000060 | ff ff ff ff 12 00 00 ff   00 00 00 00 00 00 00 00
00000070 | 20 00 ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000080 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000090 | ff ff ff ff 12 00 00 ff   00 00 00 00 00 00 00 00
000000a0 | 20 00 ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000b0 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000c0 | ff ff ff ff 12 00 00 ff   00 00 00 00 00 00 00 00
000000d0 | 00 00 00 00 20 00 ff ff   ff ff ff ff ff ff ff ff
000000e0 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
000000f0 | ff ff ff ff ff ff ff ff   12 00 00 ff 00 00 00 00
00000100 | 00 00 00 00 20 00 ff ff   ff ff ff ff ff ff ff ff
00000110 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000120 | ff ff ff ff ff ff ff ff   12 00 00 ff 00 00 00 00
00000130 | 00 00 00 00 20 00 ff ff   ff ff ff ff ff ff ff ff
00000140 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000150 | ff ff ff ff ff ff ff ff   12 00 00 ff 00 00 00 00
00000160 | 00 00 00 00 20 00 ff ff   ff ff ff ff ff ff ff ff
00000170 | ff ff ff ff ff ff ff ff   ff ff ff ff ff ff ff ff
00000180 | ff ff ff ff ff ff ff ff   12 00 00 ff

input data:
00000000 | 00 c1 00 00 00 0e 00 00   80 46 00 00 00 20

output data:
00000000 | 00 c4 00 00 00 2e 00 00   00 00 00 00 00 20 8f f7
00000010 | 11 2e c9 5a c5 2f 3e f0   4e c0 b4 cc ee e6 cb ab
00000020 | e3 15 a6 ef 4d 83 90 99   10 c1 32 89 7b 15

TCM_GetRandom Success
input data:
00000000 | 00 c1 00 00 00 50 00 00   80 bf 00 02 00 00 00 00
00000010 | 8f f7 11 2e c9 5a c5 2f   3e f0 4e c0 b4 cc ee e6
00000020 | cb ab e3 15 a6 ef 4d 83   90 99 10 c1 32 89 7b 15
00000030 | ed 51 67 25 22 6e f8 81   fa 67 36 73 fa a9 96 37
00000040 | 65 48 eb ce c8 d4 e0 1b   3c d9 ca 24 d4 75 a5 be

output data:
00000000 | 00 c4 00 00 00 52 00 00   00 00 ce e4 ee 07 49 30
00000010 | f8 39 ee e8 e5 b7 e4 16   08 1b 2c 8a 9f 40 6d 90
00000020 | 8a 8a 76 10 37 dc c1 20   fc 01 c3 a4 b4 78 10 38
00000030 | a6 aa da e2 a0 83 4e e3   4d 7a 92 88 f2 f6 e7 f5
00000040 | 0c a0 e7 6f 90 ec 1e be   5d e7 6c 86 b5 52 d9 27
00000050 | cc 45

APCreate Success
TCM_APCreate Success
sm3 data
00000000 | 00 00 80 cf 40 00 00 a1   00 00 00 00 00 00 00 30

SM3_soft result
00000000 | 87 52 ff d9 0c 2c 18 7b   74 c3 2f 80 9f 0f 81 1d
00000010 | 07 15 28 3a ad 79 9f ac   a4 f2 ec db 31 c6 0f a2

hash_Result
00000000 | 87 52 ff d9 0c 2c 18 7b   74 c3 2f 80 9f 0f 81 1d
00000010 | 07 15 28 3a ad 79 9f ac   a4 f2 ec db 31 c6 0f a2

input data:
00000000 | 00 c2 00 00 00 3a 00 00   80 cf 40 00 00 a1 00 00
00000010 | 00 00 00 00 00 30 ce e4   ee 07 f7 b5 0f 24 c8 5e
00000020 | 26 23 43 fd 98 ad 45 db   91 9e 06 0c 01 00 75 71
00000030 | 62 3c c8 3a dc c7 89 6e   27 bc

output data:
00000000 | 00 c5 00 00 00 5e 00 00   00 00 00 00 00 30 00 00
00000010 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000020 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
00000030 | 00 00 00 00 00 00 00 00   00 00 00 00 00 00 dc bb
00000040 | f8 aa 83 96 85 80 b0 c1   58 73 0c 9d c3 14 cc e6
00000050 | b7 f1 9a ff 9e e9 ff c6   37 ca b4 4a da fc

input data:
00000000 | 00 c2 00 00 00 2e 00 00   80 c0 ce e4 ee 07 ae 0b
00000010 | 94 4c da c5 eb 5f 98 7c   ce 96 34 f5 ff 89 84 61
00000020 | 57 4e 3a 1c 49 26 02 2a   c5 6d bc 8e 68 b0

output data:
00000000 | 00 c4 00 00 00 0a 00 00   00 00

fu_TCM_APTerminate success
APTerminate Success
TCM_NV_ReadValue(TCM_NV_INDEX_TPCM_2) Success
```
