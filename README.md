# XiaokuiCry

这是个简单的批量加密文件程序的雏形，包含以下几个简单的功能：

1、加密指定目录文件

2、弹出成功提示

3、清空回收站和卷影副本



程序对每个文件生成一个随机AES密钥加密，并用RSA对密钥进行加密，但是没有预置RSA密钥对，需要自行填充