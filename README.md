# 1 可信标准
国际标准TPM和中国大陆标准TCM。
## 1.1 TPM
可信平台模块TPM（Trusted Platform Module）是一项安全密码处理器（Secure cryptoprocessor）的 ***国际标准***，旨在使用设备中集成的专用微控制器（安全硬件）处理设备中的加密密钥。TPM的技术规范（Specification Technical standard）由可信计算组织TCG（Trusted Computing Group）的资讯业联合体编写。

国际标准化组织（ISO）和国际电工委员会（IEC）已于2009年将规范标准化为ISO/IEC 11889。
## 1.2 TCM
按照我国密码算法 ***自主研制的具有完全自主知识产权*** 的可信计算标准产品。TCM（Trusted Cryptography Module）由长城、中兴、联想、同方、方正、兆日等十二家厂商联合推出，得到国家密码管理局的大力支持，TCM安全芯片在系统平台中的作用是为系统平台和软件提供基础的安全服务，建立更为安全可靠的系统平台环境。

中国大陆制造TPCM芯片的公司有国民技术，可信华泰等。
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
### 非易失性存储器
主要用于存储嵌入式操作系统及其文件系统，存储密钥、证书、标识等重要数据
### 平台状态寄存器（PCR）
用来记录系统运行状态的寄存器，TPM只允许两种操作来修改PCR的值：重置操作（Reset）和扩展操作（Extend），重置操作发生在机器断电或者重新启动之后，PCR的值自动重新清零。
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
