# 基于中间人攻击的加密 C2 通信响应技术

> **项目简介**：这是一个基于中间人攻击（MITM）的 C2 流量防御框架，利用 mitmproxy 插件机制，实现对 Cobalt Strike 和 Metasploit 加密通信流量的实时解密、篡改与分析，并支持通过替换下发文件进行主动溯源反制。

建立加密 C2 通信已成为网络攻击者常用的后渗透控制阶段常用手段，广泛应用于各类攻击事件。Cobalt Stike 和 Metasploit 是最流行的 C2 工具，其 C2 服务器占比达 75%。针对 C2 通信流量加密、网络行为复杂，传统方法对抗能力有限的问题，本章节将中间人攻击技术应用于网络防御，提出基于中间人攻击的加密 C2 通信响应方法。通过在通信链路关键节点部署中间人代理，精细化解析流量，修改密钥与 TLS 证书，防御方可解密并篡改恶意流量，并基于明文流量替换被上传文件，向攻击者投递恶意文件，实现溯源反制。验证表明，该方法在多种恶意工具及其多种 Payload 类型中有效，相比流量阻断或蜜罐重定向等响应手段，显著提升对加密 C2 通信流量的控制能力，为安全运营与取证提供了新思路。

## 使用

提供的代码属于mitmproxy的插件，基于mitmproxy的python API，实现对C2 HTTP通信流量的解析、修改、替换，以实现中间人攻击。安装mitmproxy python依赖，按需要进行网络配置。
cs-mitm为针对cobalt strike的插件，msf-mitm为针对metasploit的插件。
直接运行
```
python3 cs-mitm.py
python3 msf-mitm.py

```

## 引言

一种基于中间人攻击的加密 C2 通信响应方法。该方法借鉴攻击者常用的中间人攻击技术，将其逆向应用于网络防御领域。中间人攻击技术是一种网络攻击方式，攻击者通过拦截和篡改通信双方的数据，从而获取敏感信息、篡改数据或进行身份欺骗行为，必须在合法授权的前提下进行。通过在通信链路的关键节点部署中间人代理，控制上线通信流量，发现通信过程中的中间人攻击脆弱性，篡改 TLS 证书和密钥，实现对恶意 C2 流量的解密与篡改，识别攻击者的行为模式和控制命令。进而， 防御方可以在攻击者试图窃取敏感数据时，替换为定制的攻击性文件，诱导攻击者暴露其真实身份。最终实现对恶意远控通信的实时监控和动态干预，降低数据泄露与系统破坏的风险。与传统的恶意 C2 通信响应技术相比，本文提出的方法主动防御能力强，不仅能够解密分析恶意活动，还能主动干预攻击过程，对攻击者实施反制和追踪。其次是适用于 Cobalt Strike、Meterpreter 多种恶意远控工具并可在网络环境中作为中间人代理部署，不易被攻击者察觉，不需要受保护用户有感配合，具备较强的隐蔽性和持续监控能力。本章的贡献总结如下：

1. 系统性分析了基于中间人攻击的加密 C2 通信响应技术， 对 Cobalt Strike 和 Meterpreter 攻击工具的 HTTP/HTTPS 通道上线通信加密机制脆弱性进行深入分析，提出了一种能应对加密命令控制通信和复杂网络环境的主动防御模型。
2. 通过在通信链路关键节点部署中间人代理，精细化解析流量，篡改密钥与 TLS 证书，实现了防御方对 C2 通信流量自定义加密机制和 TLS 加密机制的破解，并验证了该方法在 Cobalt Strike、Meterpreter 工具多种场景下的有效性，相比流量阻断或蜜罐重定向等响应手段，可在用户无感条件下实时解密分析加密 C2 流量，显著提升对加密通信的控制能力。
3. 在中间人劫持解密的明文的基础上探索反制策略，提出通过替换攻击者上传文件为反制程序，实现可跨越复杂网络环境的溯源反制。验证表明，替换后的文件可绕过多层网络节点后，传递至攻击者主机，并且具有较强的隐蔽性。



## 加密 C2 通信机制

分析 Cobalt Strike 和 Meterpreter 的上线与通信机制，重点介绍恶意工具的完整上线通信流程以及相关加密认证机制。

### Cobalt Strike 上线通信过程

<img src="images\CSshangxian (1)_01.png" alt="CSshangxian (1)_01" style="zoom: 67%;" />

Cobalt Strike 的上线模式可以分为分阶段（Stager）和不分阶段（Stagerless）两种模式。Stager 模式首先植入的 Stager 程序是一种轻量级的初始 Payload，负责与 C2 服务器建立第一步连接，下载具有完整控制功能的 Payload (Cobalt Strike 称为 Beacon)，Beacon 具有远程执行命令、上传下载文件、控制受害主机等强大功能。Stager 模式适用于需要快速投放和绕过安全检测的场景。即先上传一个小马（Stager），这个小马的功能就是用于下载大马（Beacon），命令控制的功能由大马实现，小马仅仅是作为一个桥梁，把大马下载到服务器上。Stageless 模式直接由攻击者将完整 Payload 直接投放到受害者主机，一旦执行即可立即上线，无需与 C2 服务器进行额外的 Payload 下载。

Cobalt Strike 的 HTTP 通道 Stager 模式上线与通信过程主要包括三个阶段：Beacon 植入、Beacon 上线、命令 & 控制。

#### （1）Beacon 植入阶段

在 Beacon 植入前，攻击者会通过钓鱼邮件、漏洞利用、水坑攻击等将 Stager 植入受害者主机，受害者主机一旦执行 Stager， Stager 首先会向 C2 服务器发起 HTTP GET 请求，目的是下载完整的恶意 Payload。该请求通常会被伪装为正常的 HTTP 请求，避免被防御系统发现，例如伪装成请求图片、CSS 文件或其他网页资源。

C2 服务器响应此请求，返回完整的 Payload——Beacon。

此时，Beacon 木马中硬编码了一个 RSA 公钥加密算法 2048 位公钥。当 Beacon 执行时，它会将此公钥用于后续的加密操作。Beacon 会在内存中执行，避免在磁盘上留下痕迹。

#### （2）Beacon 上线阶段

上线是指 Beacon 植入成功并与 C2 服务器建立通信， C2 服务器端端程序显示受害主机已被植入完整 Payload，可进行命令控制的过程。

Stager 对 Beacon 进行解码并在内存成功执行后，Beacon 会发送上线数据包（即第一个心跳包），心跳包是一个的 HTTP GET 请求。 请求中携带加密的元信息，Cobalt Strike 将元信息称为 Metadata，包含受害主机的基础信息（如系统信息、用户信息、IP 地址等）以及用于加密的密钥信息。Metadata 隐藏在 HTTP Header 的 Cookie、URI 或 其他 HTTP 请求参数中，以增加隐蔽性。

C2 服务器首次收到心跳包后返回响应，通常为一个空的 HTTP 响应体，表示当前没有新的任务下发。

Beacon 上线的过程实现了加密会话密钥的协商。

首先，Beacon 木马会生成一个 256 位 AES 对称密钥加密算法的会话密钥信息，存储在 Metadata 中，用于后续的加密通信。为了确保密钥交换过程的安全性，Beacon 木马会使用第一阶段硬编码携带的公钥对生成的 Metadata 进行加密，并由心跳包携带发送给 C2 服务器。一旦 C2 服务器收到这个加密后的会话密钥后，它便使用自己的私钥进行解密，成功获取到 AES 会话密钥信息，加密后续通信。

一旦双方完成密钥协商并共享了相同的 AES 会话密钥，后续的通信内容（包括 C2 端下发的任务、受害者端任务执行结果等）都会使用这个共享的 AES 会话密钥进行加密。这样，攻击者与受害者之间的所有通信都变得安全，外部的窃听者无法解密这些数据，除非他们拥有 AES 密钥。

#### （3）命令 & 控制阶段

之后，一旦 Beacon 成功上线，它会进入一个循环，定期与 C2 服务器进行心跳通信，检查是否有新命令下发。

如果有任务需要执行（例如执行命令、上传 / 下载文件、获取敏感信息等），则心跳包响应会携带加密的任务数据。Beacon 收到 C2 服务器的响应 使用已协商的 AES 对称密钥解密命令内容，随后在受害主机上执行相应的任务。

经过一段时间任务执行，Beacon 将命令的执行结果封装后，通过 HTTP POST 请求发送回 C2 服务器。执行结果会经过 已协商的 AES 加密，确保数据传输的安全性。 C2 服务器返回空响应，确认已成功接收执行结果。

当 Cobalt Strike 使用的 Payload 类型属于 Stageless 模式时，便不会有阶段一 Beacon 植入阶段，因为通过各种攻击方式植入的将不是 Stager，而就是具有完整功能的 Payload。

除了已经介绍的 Cobalt Strike 支持 Stager 模式 和 Stageless 模式，以及自定义的加密安全机制，Cobalt Strike 的流量还具有以下特征：

#### （1）多 Payload 类型多协议支持

Cobalt Strike 的 Beacon 支持多种通信协议，包括 HTTP、HTTPS、DNS、TCP、SMB 等协议进行上线和命令控制，本文主要研究了针对 Cobalt Strike 使用 HTTP、HTTPS 协议时的中间人攻击。

Cobalt Strike 的 Payload 也有多种植入类型，提供不同类型的恶意代码执行方式，如 Windows Stager Payload 和 Windows Stageless Payload 专门针对直接植入 Windows 系统，Scripted Web Delivery 适用于将其植入 Web 应用程序或浏览器进行攻击，以及 Stager/Stageless Payload 生成器，它可以生成多种类型的恶意代码，如 PowerShell、C 语言、Java 等，为后续的攻击提供灵活的 Payload 选项。

#### （2）支持 TLS 流量加密

除了 Cobalt Strike 自身基于 RSA 和 AES 加密算法实现的安全机制外，使用 HTTPS 通信协议时，可在发送 HTTP 请求前都会建立 TLS 连接进行服务端身份认证和流量加密伪装。

#### （3）流量伪装与混淆

Cobalt Strike 支持定制 C2 Profile，以伪装成合法网站的流量（如仿照 CDN、社交媒体等）。C2 Profile 是 Cobalt Strike 中用于定义 C2 通信的配置文件。使得 Beacon 可以在 HTTP 请求头、URI、Cookie、User-Agent 等位置灵活隐藏 C2 通信数据，并添加编码机制和增加前缀和后缀字符串模拟正常的 Web 流量，增加检测和解析分析难度。

### Meterpreter 上线通信过程

Meterpreter 对比 Cobalt Strike 的上线与通信流程区别不大，同样支持支持 Stager 模式 和 Stageless 模式上线，包含 Meterpreter 植入、Meterpreter 上线、命令 & 控制三个阶段。

上线阶段也会基于工具本身实现的加密认证机制协商生成密钥进行数据加密，也使用心跳机制以及相同的任务下发和任务结果回传流程，支持 HTTP、HTTPS、TCP、DNS 等多通信协议支持。但 Cobalt Strike 支持基于 C2 Profile 定制 C2 通信流量，相比 Meterpreter 具有更强的流量隐蔽性和抗检测能力。

## 方法设计

针对恶意远程控制上线通信流量加密的特点，本章提出基于中间人攻击的加密 C2 通信响应技术，将中间人攻击技术应用于 C2 通信流量的响应，对其上线通信过程中的自定义流量加密机制以及 TLS 加密机制进行中间人攻击劫持，并在解密明文基础上探索反制方法。本章节首先对该技术的整体架构进行介绍，之后具体讲解对 Cobalt Strike 和 Meterpreter 中的自定义流量加密机制与 TLS 中存在的脆弱性与进行中间人攻击的具体实现方法，以及文件替换反制的精细化流量修改方法。

### 方法架构

<img src="images\架构2-1769535790832-2.png" alt="架构2" style="zoom: 25%;" />

基于中间人攻击的加密 C2 通信响应技术框架核心目的是通过拦截、分析和篡改加密 C2 通信流量，提升网络防御的能力。具体架构如下：

首先基于主动探测模块，获取和分析与 C2 服务器通信的内容，基于 Jarm 指纹和 Url 碰撞探测发现 C2 服务器，记录包括 C2 服务端 IP、端口等，帮助系统定位和标记 C2 服务器信息，该技术原理在系统威胁检测模块实现中详细说明。之后由流量拦截牵引模块对 C2 服务器的通信流量进行流量拦截，并牵引至流量中间人攻击劫持平台，能够实现对流量的解密、篡改，进一步用于分析和反制。

在中间人平台中， 针对 HTTPS 和其他基于 TLS 的加密流量，系统能够替换或修改证书，进行解密操作，获取加密通信内容。除了 TLS 加密认证外，系统还支持对自定义加密协议的解密。通过分析通信数据包内容和加密机制，替换密钥协商过程公钥，获取会话密钥，能够实时解密恶意流量。解密后的数据内容被解析为通信明文，可进一步分析恶意指令、数据窃取行为等，识别潜在的攻击活动。通过识别和分析下载文件的流量，系统能够主动替换恶意下载的文件，将其替换为攻击性文件传递至攻击者主机，实现进一步的反制操作，避免敏感信息泄露。

### 自定义加密协商劫持方法

#### Cobalt Strike 工具中间人攻击脆弱性分析

Cobalt Strike 可以使用 Stager 模式进行恶意 Payload 的上线，其 Windows Stager Payload、Scripted Web Delivery、Stager Payload Generator 生成的恶意样本建立 C2 通信都使用了 Stager 模式。

在 Cobalt Strike 的 Stager 模式上线过程中，使用 RSA 非对称加密算法和 AES 对称加密算法的组合实现了自定义的安全机制。

这是典型的 DH (Diffie-Hellman) 密钥协商应用，DH 密钥协商是一种公钥交换协议，允许两方在不安全的通信信道上共同生成一个共享的密钥，这个共享密钥可以用作对称加密算法（例如 AES）的密钥，用于后续的安全通信。DH 依赖于非对称加密的概念，在非对称加密算法中，公钥（Public Key，PK）是公开的，可以被任何人获取，用于加密数据。私钥（Private Key，SK）是私密的，仅由持有者自己掌握，用于解密数据。

Cobalt Strike 所使用的 RSA（Rivest-Shamir-Adleman）算法是最著名的公钥加密算法之一，广泛用于密钥协商和数字签名。它基于大整数因子分解的数学难题，在加密和解密过程中使用一对密钥 —— 公钥和私钥。即使公钥被监听，攻击者也无法轻易推算出共享密钥，因为破解私钥需要极大的计算量。RSA 算法首先由每个用户生成一对密钥，包括公钥 PK=(e,n)，其中 e 是公钥指数，n 是模块值，以及私钥 SK=(d,n)，其中 d 是私钥指数。公钥是公开的，任何人都可以使用它进行加密，而私钥是保密的，仅持有者拥有，私钥用于解密。

假设发送方的明文为 m，接收方的公钥为 PK=(e,n)，则加密过程如公式 (1) 所示，其中，c 是密文，m 是原始的明文消息，e 是公钥指数，n 是模数。

c=memodn(1)

接收方使用自己的私钥 SK=(d,n) 来解密密文 c，解密公式如 (2) 所示，其中，m 是解密后的明文，c 是密文，d 是私钥指数，n 是模数。

m=cdmodn(2)

通过以上过程，可以看到公钥加密的加密与解密是通过不同的密钥进行的，确保了即使公钥被公开，信息的安全性依然得到保障。

已有利用已知公钥对应的私钥来进行离线解密 Cobalt Strike 加密通信流量的工作，如由于破解版本被广泛使用，NVISO 的研究人员发现超过四分之一的公网 Cobalt Strike 服务器使用相同的加密公钥密钥对。通过这些密钥，便能够解密 Cobalt Strike 的自定义加密算法加密的流量。

在本章节的方法中，也可以去缓存一些公钥对应的私钥进行碰撞，进而解密出 AES 会话密钥来还原原始通信数据。

但本章考虑更通用的场景，若 Beacon 携带的公钥对应私钥不已知，进行加密流量劫持和中间人攻击。

DH 密钥协商的问题在于本身不提供身份认证，无法证明公钥来自通信对方，攻击者可能会进行中间人攻击来窃取会话密钥。要么公钥需要提前存 储于受害者主机，要么配合与其他身份验证方法（如数字签名）结合使用，以确保安全性，否则公钥跟随恶意代码进行传输存在篡改的风险。

本章节验证了在 Cobalt Strike 的自定义加密协议通信过程中，通过公钥篡改进行中间人攻击的有效性，中间人攻击流程如下图所示。

<img src="images\cs-mitm-1769535805640-4.png" alt="cs-mitm" style="zoom: 33%;" />

##### （1）阶段一：Beacon 植入

在阶段一的 Beacon 木马的植入过程中，携带 C2 端的 RSA 公钥的 Beacon 会响应给 Stager 并在内存中运行。然而，攻击者可以通过中间人攻击劫持这个过程，解析还原流量中的 Beacon 下载数据流并替换 Beacon 木马内置的 RSA 公钥。替换规则可以根据公钥的前缀进行定位，从而精准替换为中间人持有的公钥。

##### （2）阶段二：Beacon 上线

Beacon 木马在受害者主机内存执行时，会生成计算 256 位的 AES 会话密钥的随机数，随机数包含在 Metadata 中，并发送至 C2 端，用于后续的对称加密通信。此时，Beacon 会使用中间人攻击者替换的公钥对 Metadata 加密，存储至心跳包发送给 C2 端。

作为中间人，中间人定位 Beacon 植入受害主机后发出心跳包请求中的 Metadata，使用自己替换的公钥对应私钥来解密 Metadata，从而计算获得明文的 AES 密钥。然后，攻击者使用 C2 端的公钥将 Metadata 重新加密，并将其发送到 C2 端。这样，C2 端将接收到一个由攻击者重新加密的有效 Metadata，可以由 C2 端私钥进行解密，避免感知中间人攻击存在。

##### （3）阶段三：命令 & 控制

一旦会话密钥成功传输并验证，受害者主机与 C2 端之间的通信将使用此 AES 会话密钥进行加密。中间人攻击者能够在后续的通信中通过协商的 AES 会话密钥解密和篡改传输的数据，实现对通信内容的完全控制。

#### Cobalt Strike 中间人攻击方法实现

<img src="images\cs-mitm-流程.drawio (2)_01.png" alt="cs-mitm-流程.drawio (2)_01" style="zoom: 67%;" />

以下介绍实现中间人攻击过程中，对 Cobalt Stike 建立的 C2 通信中不同阶段不同功能数据包的类型匹配、解析、加解密和具体修改方法。

**算法 1 Cobalt Strike 流量劫持算法**

```
输入：HTTP数据包
输出：篡改后的HTTP数据包
while 读取HTTP数据包:
    if flow.request:  # Beacon端请求数据
        if flow.request.method == GET:
            if Cookie in flow.request.headers:  # Beacon心跳请求
                metadata = RSADecrypt(Cookie, sk_mitm)
                dict[ip三元组].rawKey = metadata[8:8 + 16]
                Cookie=RSAEncrypt(metadata, dict[ip三元组].pk_cobalt strike)
        if flow.request.method == POST:
            if flow.request.content != b'':  # Beacon上传任务结果
                content = AESDecrypt(content, dict[ip三元组].rawKey )
                if 解析content存在文件上传:
                    替换为反制文件
    if flow.response:  # C2端响应数据
        if flow.request.method == GET:
            if 'Cookie' not in flow.request.headers && flow.request.path 符合cs生成URl格式:  # C2下载Beacon响应
                Beacon公钥替换，并记录Cobalt Strike使用公钥至dict
            else:  # C2端心跳响应
                明文数据 = AESDecrypt(content, dict[ip三元组].rawKey )
                解析明文数据，记录C2端任务
        if flow.request.method == POST:  # C2端任务结果响应包
            Pass
```

具体实现针对以下数据包进行拦截处理，之后分别介绍对这些数据包的类型匹配和处理方式：

- 阶段一 Beacon 植入的 HTTP 响应报文。
- 阶段二 Beacon 上线和阶段三命令控制阶段心跳包 HTTP GET 请求和响应。
- 阶段三 Beacon 发送任务执行情况的 HTTP POST 请求。

##### (1) 阶段一 Beacon 植入的 HTTP 响应报文

首先，对于 HTTP 响应需要判定该报文为阶段一 Beacon 植入的 HTTP 响应报文，中间人根据 HTTP 响应对应请求的方法为 GET，且请求的 url 符合 Cobalt Strike 生成 url 的规则来判定。url 判定规则为使用 checksum8 算法，计算 url 的校验和是否为 92 或 93。校验和为 92 代表该 url 下载的是 Cobalt Strike 所生成 x32 类型 Beacon 木马，93 代表下载的是 Cobalt Strike 生成 x64 的 Beacon 木马。

之后需要解析定位流量接收的 Beacon 中公钥位置，并进行替换。具体替换流程如算法 2 所示。

**算法 2 Cobalt Strike 下载 Beacon 公钥替换算法**

```
输入：Beacon下载HTTP响应内容content
输出：替换公钥后的Beacon下载响应
if content 以"$s=New-Object IO.MemoryStream"为起始:
    # scripted Web dilivery类型
    beacon = Decode1(content)
    pkStart = beacon.find(b'30819f300d06')  # 定位公钥
    dict[ip 三元组].pubKey = beacon[pkStart:pkStart+256]
    beacon[pkStart:pkStart+256]  = pk_mitm  # 替换公钥
    contentMotified = Encode1(beacon)
else:
    # Stager Payload类型
    beacon = Decode2(content)
    if beacon有PE文件头:
        pkStart = beacon.find(b'30819f300d06')  # 定位公钥
        dict[ip 三元组].pubKey = beacon[pkStart:pkStart+256]
        beacon[pkStart:pkStart+256]  = pk_mitm  # 替换公钥
        contentMotified = Encode2(beacon)
    else:
        结束
return contentMotified
```

由于 Cobalt Strike 收到 Beacon 程序后会在内存以 PE 文件运行，并且在流量传输时存在混淆和编码的操作，所以在定位替换公钥前对 Beacon 流量进行解析。目前已有一些对下载 Beacon 数据流及 PE 文件进行解析的相关工作。通过对 Cobalt Strike 解码方式的代码分析，此过程并不涉及基于密钥的加密算法，只是 base64 编码、异或、链式异或、在前后加入冗余数据等进行流量混淆。且研究发现 Stager Payload 和 Script Web dilivery 在下载 Beacon 时的流量特征不同，所以本方法判断不同 Payload 类型进行不同的解析解码方式，如 Script Web dilivery 类型 Payload 以‘$s=New-Object IO.MemoryStream’开头，Stager Payload 类型 Payload 使用了链式异或进行流量混淆。具体解析过程较为复杂，本章节不再进行详细说明，本方法基于已有工作分析，对可能经过混淆的 Beacon 下载流量进行了解析还原（Cobalt Strike 通过 Profile 配置文件支持自定义的灵活编码混淆，可能存在无法成功解析的情况）。

对于定位公钥在文件中的起始位置，本方法避免解析完整 Beacon 程序根据标识得到公钥位置所导致的长时延，选择直接进行公钥查找并替换，查找的标志为 Cobalt Strike 使用 RSA 公钥在 DER（Distinguished Encoding Rules）编码格式中的前缀。

DER 是一种用于编码 X.509 证书、公钥等数据的标准格式，常用于在网络中传输数据。DER 编码是二进制编码格式，遵循 ASN.1（Abstract Syntax Notation One）标准，用于描述数据结构。

在 DER 编码格式 下，RSA 公钥被编码为二进制流，包含 算法标识符 和 公钥数据（即 模数 n 和 公钥指数 e）。  RSA 公钥 DER 编码格式以 0x30819f300d06092a864886f70d0101010500 为起始，包含 RSA 算法的 OID。本方法以特定字节长度 0x30819f300d06 的公钥前缀进行匹配，查找字符串位置pkStart作为公钥的起始位置。

之后提取原始 Beacon 的pkStart至pkStart+256位置为 Cobalt Strike 的 C2 服务端公钥pkcs，替换为中间人公钥pkmitm。由于 Beacon 每次请求可以使用新的 TCP 连接，本方法基于 IP 三元组（源 IP、目的 IP、目的端口）为键，C2 服务端公钥pkcs与会话密钥信息为值，进行原始 C2 端密钥的存储。

##### （2）阶段二 Beacon 上线和阶段三命令与控制阶段的心跳包 HTTP GET 请求和响应

Cobalt Strike 的 心跳包 HTTP GET 请求中携带的唯一信息为 Metadata。

Metadata 是其 Beacon 工具与 Cobalt Strike C2 服务端 之间通信的核心部分，包含关于被攻击主机的关键信息和密钥信息。Metadata 结构包括 Magic Number (0xBEEF)、16 字节随机值、字符集、Beacon ID 和进程 ID、端口、Beacon 架构类型标志、Beacon 版本和构建版本、函数指针、目标 IP 地址、计算机名、用户名以及 Beacon 进程名等其他信息。

Metadata 中的 16 字节随机值用于生成 AES 密钥和 HMAC 密钥，Beacon 在启动时生成 16 个随机字节，这些字节是唯一的，每次执行时都会有所不同。这些字节用于生成 AES 和 HMAC 密钥，具体实现方式是用这 16 字节计算 SHA256 哈希，前 16 字节作为 AES 密钥进行对称加密，后 16 字节作为 HMAC 密钥进行消息认证。

首先本方法默认通过 Cookie 得到加密 Metadata 数据（但 Metadata 数据可能不存在于 Cookie 字段，且可能经过自定义的编码混淆），使用中间人 RSA 私钥进行解密后，提取明文 Metadata 的第 8 至 24 字节随机值，作为本次 C2 通信会话以 IP 三元组为键的原始密钥信息。之后获取阶段一捕获的 Cobalt Strike C2 端原始 RSA 公钥对明文 Metadata 进行加密，最后修改至 Cookie，返回篡改后的心跳包。

对于心跳包的响应，本方法根据其对应请求的方法为 GET，不为下载 url 的特定格式，且已有三元组对应记录来判断。之后提取通信三元组对应的原始密钥信息，解密响应内容，记录 C2 端发送的任务。

##### （3）阶段三 Beacon 发送任务执行情况的 HTTP POST 请求

本方法根据请求的方法为 POST 来定位这一报文，因为这是唯一使用 POST 请求的报文。基于 IP 三元组获取通信的 16 字节随机值计算会话密钥，并进一步解密 HTTP 请求报文内容。得到明文后进行解析，可在判断存在文件上传任务执行结果时进行攻击性文件替换，后续章节将进行详细介绍。

#### Meterpreter 中间人攻击脆弱性分析

Meterpreter 的通信信道包括 HTTP、HTTPS 等，在 HTTP 信道中，Meterpreter 使用自定义实现的密钥协商和加密来保护流量的隐蔽性，防止明文数据传输。以 Meterpreter/Reverse_HTTP（HTTP 信道的 Meterpreter）为例对 Meterpreter 的自定义加密实现进行分析。

从流量侧，Reverse_HTTP 的 Stager 分阶段上线流程同样可简单总结为：

阶段一 Meterpreter 植入，阶段二 Meterpreter 上线，阶段三命令 & 控制。

在阶段一 Meterpreter 植入阶段，与 Cobalt Strike 工具将 C2 端公钥固定在完整 Payload 不同，Meterpreter 并不会把 C2 端公钥固定于完整 Payload 木马程序，而是在 Meterpreter 木马程序在内存运行后与 C2 端进行通信时再由 C2 端将公钥传输给木马受控端。

在三阶段的 C2 通信正式开始之前，Metasploit 服务器与受控机器上的 Meterpreter 木马程序需要进行密钥协商过程：

首先，Metasploit C2 服务器会生成一个 2048 位的 RSA 密钥对，包含公钥和私钥。该公钥被封装在一个 TLV 编码的数据结构中，并与 core_negotiate_tlv_encryption 命令一起发送到植入受害者的 Meterpreter。Meterpreter 接收到该数据包后，会解析并提取其中的公钥。接着，客户端会随机生成一个 256 位的 AES 密钥，并使用从服务器获得的公钥对这个 AES 密钥进行加密。客户端会将包含加密后的 AES 密钥的包发送回 Metasploit 服务器。

一旦密钥协商完成，双方将丢弃生成的 RSA 密钥对，并使用协商后的 AES 密钥来加密所有后续数据包。

Meterprter 的 C2 通信数据包结构如下图，在通信过程中，Metasploit 服务器与 Meterpreter 客户端之间的所有数据都通过严格的 TLV 编码方式传输，且外层采用 XOR 加密，XOR 密钥为每个数据包的前 4 个字节。内层包括：会话 ID，用于标识当前会话的唯一标识符。加密标志，指示数据包是否被加密以及加密方式。如果加密标志为 0，则后续数据包结构即为 TLV 编码；如果加密标志为 1，则数据包结构会发生变化，后续数据包内容除了 TLV 编码外，还会包含 16 字节的初始化向量（AES IV）用于 AES256 解密，并且接下来是 AES 加密的 TLV 载荷。

<img src="images\mt-tlv (2).png" alt="mt-tlv (2)" />

<img src="images\mt-tlv2 (2).png" alt="mt-tlv2 (2)" />

尽管 C2 服务器与 Meterpreter 之间的通信已使用加密保护措施，但仍然存在一定的解密风险，尤其是在中间人攻击中。中间人可以在 Meterpreter 接收 C2 服务器发送的 RSA 公钥之前，将其替换为中间人的公钥。这样，Meterpreter 会错误地使用中间人的公钥加密 AES 密钥，而不是 C2 服务器的公钥。中间人通过使用自己的 RSA 私钥解密获取 AES 密钥，并再用 C2 服务器的公钥对其加密，确保 C2 服务器能够正常接收到正确的 AES 密钥。这种方式使得中间人能够获取 AES 密钥，并能够解密后续的所有通信数据。

#### Meterpreter 中间人攻击方法实现

**算法 3 Meterpreter 流量劫持算法**

```
输入：HTTP数据包
输出：篡改后的HTTP数据包
while 读取HTTP数据包:
    if flow.request:
        Meterpreter报文异或解码
        if 加密标识==0:
            解析TLV格式明文
            if TLV_Data_Type == 550 :  # RSA公钥
                dict[ip三元组].pubKey = TLV_Data_Value
                TLV_Data_Value=pk_msf
                明文篡改后进行重新编码
        if 加密标识==1:
            TLV_Data=AESDecrypt(TLV_Data_enc,dict[ip三元组].aesKey )
            解析TLV格式明文TLV_Data
    elif flow.response:
        Meterpreter报文异或解码
        if 加密标识==0:
            if TLV_Data_Type == 553 :  # 会话密钥
                aesKey = RSADecrypt(TLV_Data_Value, sk_mitm)
                dict[ip三元组].aesKey = aesKey
                TLV_Data_Value = RSAEncrypt(metadata, dict[ip三元组].pk_msf)
        if 加密标识==1:
            TLV_Data=AESDecrypt(TLV_Data_enc, dict[ip三元组].aesKey )
            解析TLV格式明文TLV_Data
```

对 Meterpreter 的中间人攻击拦截 HTTP 通信流量，编写流量解析处理程序进行 C2 服务器与 Meterpreter 之间的通信流量的处理，解析包括异或以及 TLV 格式数据解码。

根据上述 Meterpreter 数据包结构，Meterpreter 通过加密标识表示是否进行 AES 加密，RSA 密钥协商存在于 AES 未加密阶段，且 Meterpreter 传输公钥时的 TLV 格式类型 Tlv_Data_Type 标识为 550，所以对于服务端的 HTTP 响应，在加密标识为 0 且 Tlv_Data_Type 为 550 时，本方法替换 Tlv_Data_Value 为中间人生成的 2048 位的 RSA 公钥。

在拦截 Meterpreter 客户端的请求时，对于加密标识为 0，且 TLV 的类型标识以 553 的 TLV 内容的值即为客户端随机生成的 256 位 AES 密钥，本方法首先使用中间人的 RSA 公钥对应私钥进行解密，之后记录 Meterpreter 客户端生成的 AES 密钥并以受害者 IP、C2 服务器 IP、C2 服务器端口三元组为键进行存储，该 AES 密钥可解密 Meterpreter 客户端与 C2 端的后续通信流量。

最后，本方法要重新使用 Metasploit C2 服务端原本公钥进行加密，防止 MSF 服务端无法解密 AES 密钥导致受控端上线失败。

对于拦截到的加密标识为 1 的请求与响应，代表其以进入命令与控制阶段，本方法基于三元组数据获取协商的 AES 密钥，进行内容解密，之后可进行明文内容的深度分析和修改控制。

### TLS 劫持方法

本节对 Cobalt Strike 和 Meterpreter 使用 HTTPS 通道时 TLS 认证加密受到中间人攻击的脆弱性进行分析，并详细了说明可用攻击方法，分析结果如下表所示。

首先对 Meterpreter 进行分析，因为 Meterpreter 文档对其 Payload 的 TLS 认证加密实现进行了详细阐述，相比 CoabltStrike 有着更复杂的设计开发，并且 Meterpreter 的源码公开，可以对 TLS 认证实现部分代码进行分析。Meterpreter 主要使用 WinInet 或 WinHTTP 进行 HTTPS 通信。这两种 API 在调用方式上相似，许多函数接口基本相同，转换起来相对容易，但它们在底层实现上存在一些关键区别。WinHTTP 相比 WinInet 的特点之一为支持更深入的 HTTP/S 通信控制，允许更灵活的实现。

WinHTTP 方式支持 Paranoid Mode，提供 SHA1 证书哈希固定功能，允许用户通过 HandlerSSLCert 选项在生成远控程序 Meterpreter 时提前配置 C2 服务器的 SHA1 证书哈希，确保 Meterpreter 仅与特定的 TLS 证书认证的 C2 端通信。如果服务器的证书哈希不匹配，Meterpreter 会立即终止连接，从而有效防止中间人攻击。该技术也被称为 TLS 证书固定。

虽然 Meterpreter 使用了 TLS 协议，但通过替换证书进行中间人攻击实际验证，不论 Meterpreter 使用 WinInet 或 WinHTTP 进行 HTTPS 通信，如不使用 HandlerSSLCert 选项，默认情况下都不会验证 TLS 证书的有效性，包括验证是否由受信任的 CA 颁发、通用名称（Common Name，CN）匹配、证书吊销状态等。因此，默认情况下，它无法防止中间人攻击。

基于 Meterpreter 源码进行分析，其在使用 WinInet 或 WinHTTP 时配置了以下 TLS 证书验证相关参数：

- SECURITY_FLAG_IGNORE_UNKNOWN_CA：忽略不可信 CA 签发，允许自签名证书。
- SECURITY_FLAG_IGNORE_CERT_DATE_INVALID：忽略证书日期错误。
- SECURITY_FLAG_IGNORE_CERT_CN_INVALID：忽略证书 CN 不匹配。
- SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE：忽略用途错误。

这同样验证了默认情况下，Meterpreter 受控端不会执行严格的 TLS 证书验证：不会检查 TLS 证书的可信性，可以信任任何 自签名、过期或伪造的证书。

**表 1 TLS 实现脆弱性分析**

| 恶意远程控制工具 |                Payload 类型                 |   API   | 是否验证证书可信 | 是否验证 证书哈希 |
| :--------------: | :-----------------------------------------: | :-----: | :--------------: | :---------------: |
|   Meterpreter    |                reverse_https                | WinInet |        否        |        否         |
|                  |              reverse_winhttps               | WinHTTP |        否        |        否         |
|                  | reverse_winhttps (配置 StagerVerIfySSLCert) | WinHTTP |        否        |        是         |
|   CobaltStrike   |                  全部类型                   | WinInet |        否        |        否         |
|                  |                  全部类型                   | WinHTTP |        否        |        否         |

Cobalt Strike 中上线通道支持 HTTPS 协议，但经过分析与实际验证，本研究发现不管证书是自签名，还是 CA 为 C2 端域名颁发的可信证书，Cobalt Strike 均不会对证书进行有效性校验。这使得中间人可以将 C2 端证书更换为任一中间人伪造自签名证书，与 Beacon 通过中间人自签名证书建立 TLS 连接，并且和 C2 端也建立一个连接实现解密 TLS 加密流量。Cobalt Strike 的 TLS 加密仅仅起到了流量混淆的作用，由于其生成的木马端不做证书校验，所以 TLS 提供的防止中间人攻击的服务端身份认证功能不起作用。同时 Cobalt Strike 基于 WinInet API 进行 HTTP/S 协议实现， 4.9 版本后增加了 winHTTP 的实现，但直到最新的 4.10.1 版本仍不支持 SHA1 证书哈希验证。

### 文件替换反制

在实现自定义加密协议和 TLS 协议的加密通信中间人攻击之后，可以对明文流量进行更精细化的解码、分析与篡改，探索可以反制攻击者的方法。本章节基于劫持破解后的明文流量验证实现了文件替换反制方法，反制模型如下图所示，在攻击者窃取文件（如涉密、机密和隐私文件）时进行文件替换，替换为中间人所开发的用于反制的程序文件，文件存储至 C2 服务器。若攻击者想要查看下载的受害者文件，Cobalt Strike 提供从 C2 服务器下载文件的图形化界面，支持下载文件到攻击者本地主机。攻击者打开运行该文件，即可透过各种网络伪装节点和 C2 服务端对攻击者进行反制溯源。本章节验证了这一反制方法对于 Cobalt Strike 的具体实现方法。

<img src="images\cs-file-change_01.png" alt="cs-file-change_01" />

在 Cobalt Strike 经过中间人攻击解密的明文流量中，若检测到攻击者下载受控机器上的文件行为，中间人进行文件替换。检测的方式为规则匹配。Cobalt Strike 上传数据包格式如下图，以 HTTP 信道为例，排除流量混淆的内容之后受控端 Beacon 上传的数据内容为 AES 加密的密文，密文前 4 字节为密文长度，后 16 字节为 HMAC 消息认证码。密文解密后的数据的前 4 字节表示计数器 counter 用于标识该消息的顺序或唯一性，紧接着的 4 字节表示 callback length 回调内容长度、之后 callback type 回调类型这个字段决定了数据的后续解析方式，它是一个 4 字节的值，表示当前消息的类型。不同 callback type 其回调内容不同，本方法主要关注与文件上传相关的回调数据包。

<img src="images\cs-packet (1).png" alt="cs-packet (1)" style="zoom:25%;" />

Cobalt Strike 支持文件上传和下载功能，这通常用于渗透测试中的文件转移操作。文件上传数据内容格式如下图所示。DOWNLOAD_START（回调类型 2）用于开始受害主机文件下载至 C2 服务器任务，其作用是创建目标文件，在回调内容中包括文件 ID，用于标识文件；文件大小，用于确定文件下载的预期大小；文件路径，目标文件的路径，指示下载目标文件在受害者端的存储位置。之后通过 DOWNLOAD_WRITE（回调类型 8）将解密后的数据写入到已创建的文件，回调内容字段包含文件 ID 以及完整的文件内容。最后以 DOWNLOAD_COMPLETE（回调类型 9）标志文件 ID 下载任务结束。

<img src="images\cs文件替换-1769535986955-11.png" alt="cs文件替换" style="zoom:25%;" />

中间人要修改的字段包括 DOWNLOAD_START 回调中的文件大小字段，DOWNLOAD_WRITE 回调中的 callback Length 及文件具体内容。

## 实验和评估

### 实验环境搭建

为了测试前述的加密 C2 通信响应方法，对方法进行了实验评估，实验环境如下图所示，环境选择了 Kali-rolling 2023.3 系统虚拟机作为中间人主机，Windows 10 系统虚拟机作为受害主机，Ubuntu 20.04 系统云服务器作为 C2 服务器。

<img src="images\实验环境-1769535997065-13.png" alt="实验环境" style="zoom: 25%;" />

本次实验环境中的 中间人主机 与 受害主机 都部署在 VMware 虚拟机中，C2 服务器 则部署在 阿里云云服务器 上。本章节模拟了一个中间人劫持环境，受害者主机的所有流量都经过中间人主机。具体实现方式为：在受害者主机和中间人主机之间配置虚拟机的 NAT 网络模式，并在受害者主机的 路由表 中设置中间人主机的 IP 为默认路由，同时删除原有的默认路由。

在中间人主机上，本章节使用 Iptables 设置流量转发规则，将目的 IP 和端口指向 C2 服务器的流量转发至中间人的代理程序。中间人代理程序中，使用 MitmProxy 进行透明代理、流量分析和修改。选择 MitmProxy 是因为 MitmProxy 提供了强大的流量透明代理、分析和修改功能，支持 HTTP 和 HTTPS 流量的实时劫持处理。提供 TLS 劫持支持，能够自动化替换 TLS 证书，建立客户端与服务端的双向 TLS 连接。支持透明代理模式，模拟真实中间人环境。支持插件开发，可以通过 Python 脚本实现通信流量数据的自动化解析与修改。

本实验基于以上环境实现了中间人劫持，并对提出的加密 C2 通信响应方法进行评估验证。

### 加密 C2 通信中间人攻击适用性验证

#### Cobalt Strike 中间人攻击验证

本实验选择 Cobalt Strike 的版本为 4.9.1，为 2023 年 10 月 10 日由官方发布，本实验选择 2023 年 11 月 6 日由[ddosi.org](https://ddosi.org/)发布的该版本的破解版。使用 Cobalt Strike 生成以下四种 Payload 植入受害主机，包括 Windows Stager Payload、Scripted Web Delivery、Stager Payload generator（PowerShell 代码植入类型）以及 Windows Stageless Payload，在每种 Payload 又同时使用 HTTP 以及 HTTPS 两种通信信道进行实验。

**表 2 Cobalt Strike 中间人攻击劫持有效性验证**

| 通信协议 |             Payload 类型              | TLS 加密劫持 | 自定义加密劫持 |
| :------: | :-----------------------------------: | :----------: | :------------: |
|   HTTP   |        Windows Stager Payload         |              |       √        |
|          |         Scripted Web Delivery         |              |       √        |
|          | Stager Payload generator (PowerShell) |              |       √        |
|          |       Windows Stageless Payload       |              |       ×        |
|  HTTPS   |        Windows Stager Payload         |      √       |       √        |
|          |         Scripted Web Delivery         |      ×       |                |
|          | Stager Payload generator (PowerShell) |      √       |       √        |
|          |       Windows Stageless Payload       |      √       |       ×        |

本实验的评估指标包括在本章节提出的方法中是否能实现自定义加密实现的劫持，是否能实现 TLS 加密劫持。对于 Coablt Strike 恶意远程控制工具，在使用 HTTP 通信协议时，Winodws Stager Payload、Scripted Web Delivery 以及 Stager Payload generator 这三种 Payload 类型都使用了 Stager 分阶段上线的模式，首先传递小巧的 Stager，由 Stager 下载完整的控制程序，这时就可以在 Stager 下载完整 Payload 时定位携带公钥位置进行篡改，并在上线时获取会话密钥并重新使用原公钥加密，进行工具自定义加密的中间人攻击。使用本章提出的方法在本节的实验环境中进行实验验证，此三类工具可以通过中间人攻击实现自定义加密劫持，解密通信明文数据。

对于使用 HTTP 通信协议的 Windows Stageless Payload，上线模式为 Stageless。其没有类似 Stager 下载完整 Payload 植入的阶段一，入侵受害主机后首次植入的就是具有完整控制功能的 Payload，所以 Stageless 上线模式 Pyaload 无法在与 C2 通信流量中进行公密的篡改替换，无法实现 CobaltStrike 自定义加密的中间人攻击。

<img src="images\中间人劫持展示2-1769536010718-15.png" alt="中间人劫持展示2" style="zoom: 33%;" />

针对 HTTPS 通信协议，Cobalt Strike 的 Winodws Stager Payload、Scripted Web Delivery 以及 Stager Payload generator 这三种类型 Payload 均可使用 Mitmproxy 的证书替换、TLS 劫持模块实现 TLS 加密的中间人攻击，能够解密出 TLS 加密的 HTTP 报文明文数据，基于本章分析， Cobalt Strike 只基于 WinInet API 进行开发，不支持 SHA1 证书哈希验证，若使用工具本身实现而不做二次开发，TLS 流量只用于流量混淆伪装 HTTPS 流量而忽视了其通过证书对服务端身份验证的作用。

基于对自定义加密机制和 TLS 机制的中间人攻击，中间人可以在命令控制阶段进行控制指令和指令返回结果的解密，进一步实现分析和反制。中间人攻击对 CobaltStrike 的加密流量解密效果如上图所示，攻击者在 Cobalt Strike 客户端远程控制控制受害者主机，执行文件探查操作，该控制指令通过心跳包响应发送给受害主机中运行的 Beacon。中间人基于 C2 通信上线阶段劫持的 AES 密钥，可以实时解密解析出控制命令为文件探查（LIST FILES）。Beacon 执行完指令后，通过 HTTP POST 发送指令执行结果，中间人实时解密后可以看到受害主机上传了当前的文件树，数据传递至 Cobalt Strike 客户端也展示了文件树。

#### Meterpreter 中间人攻击验证

对于 Meterpreter，选择实验版本为 6.4.44，为 2025 年 1 月 8 日由官方发布版本。Payload 类型选择 Reverse_HTTP、Reverse_HTTPS、reverse_winhttp、reverse_winhttps 以及 reverse_winhttps 并配置 HandlerSSLCert。使用本章提出的方法以及实验环境对有效性验证结果如下表所示。

**表 3 Meterpreter 中间人攻击有效性验证**

| 通信协议 |              Payload 类型              | TLS 加密劫持 | 自定义加密劫持 |
| :------: | :------------------------------------: | :----------: | :------------: |
|   HTTP   |              reverse_http              |              |       √        |
|          |            reverse_winhttp             |              |       √        |
|          |        Meterpreter_reverse_http        |              |       √        |
|  HTTPS   |             reverse_https              |      √       |       √        |
|          |            reverse_winhttps            |      √       |       √        |
|          | reverse_winhttps (配置 HandlerSSLCert) |      ×       |                |

在本节的实验环境中对 Meterpreter 的进行本章所提出方法的适用性和有效性评估验证。在使用 HTTP 通信协议时，Payload 类型使用 reverse_http 以及 revers_winhttp 时，Mterpreter 自身自定义加密机制可被中间人攻击，实现通信密文的解密，这两种类型 Payload 也同样使用 Stager 模式进行上线。在使用 Payload 类型为 Meterpreter_reverse_http 时，其上线方式为 Stageless，同 CobaltStrike 的 Stagerless 上线方式一样，但植入的完整 Meterpreter 并不固定 RSA 公钥，而是在上线时通过网络传输公钥，所以可以基于 Stager 模式公钥替换方法进行中间人攻击，经过验证也证明了可行性。

在使用 HTTPS 信道时，基于本章之前的分析，Meterpreter 使用 winhttp API 实现了 TLS 证书固定功能，但在使用 Payload 类型为 reverse_https 和未配置 HandleSSLCert 选项的 reverse_winhttps 时，仍然可以使用 Mitmproxy 实现的 TLS 劫持，通过替换证书实现 TLS 加密劫持。但在使用了 reverse_winhttps 并配置 HandlerSSLCert 选项在生成的 Stager 中固定 TLS 证书哈希值后，便无法进行 TLS 的协议的中间人攻击。

<img src="images\meterpreter展示3-1769536020716-17.png" alt="meterpreter展示3" />

基于对自定义加密机制和 TLS 机制的中间人攻击，本研究对 Meterpreter 的加密流量解密效果如上图所示。C2 服务器中的 metasploit 框架开启监听器，接收到植入受害主机的 Meterpreter 恶意程序上线后，攻击者执行 getprivs 控制指令。中间人基于之前劫持破解出的 AES 密钥解密 HTTP 心跳包响应，可得到 C2 端下发 GETPRIVS 指令。受害主机执行指令，返回用户具备权限，中间人截获 HTTP POST 数据包解密得到指令执行结果，得到用户具备 SeshutdownPrivilege 等权限，C2 端收到请求也在终端展示了用户所具备权限列表。

本节的实验证明了本章提出的针对 Cobalt Stirke 与 Meterpreter 的中间人攻击方法在多种类型 Payload 以及 HTTP、HTTPS 通信协议中的适用性和有效性。安全防御人员在监测到 Cobalt Strike 与 Meterpreter 在使用特定方式进入侵后恶意持久远程控制阶段时，可使用中间人攻击进行响应，实现通信流量的解密，支撑攻击行为分析，并可支撑进一步的流量篡改实现反制溯源。

### 文件替换反制隐蔽性评估

本节对 Cobalt Strike 替换后文件的隐藏性进行了评估，在实验环境模拟攻击者使用 Cobalt Strike 植入完整控制程序 Beacon 后，进行文件查看，并对某攻击者感兴趣的文件进行下载。该 Beacon 流量已被中间人攻击劫持，本节基于前述文件替换反制方法进行文件替换，观察文件上传 C2 服务器后，在攻击者 Coablt Strike 客户端界面中展示的文件列表中，文件信息是否发生改变，是否可能造成攻击者怀疑，评估文件替换方法隐蔽性。以及在攻击者从 C2 服务器下载至本地执行后，是否已被成功替换并成功运行。

评估具体指标如下表所示。

**表 4 文件替换反制隐藏性评估**

|     评估指标     |              说明              | 是否满足 |
| :--------------: | :----------------------------: | :------: |
|   文件名隐藏性   |  替换后的文件是否保留原文件名  |    是    |
|  文件路径隐藏性  |  文件存储路径是否符合原始路径  |    是    |
| 文件扩展名隐藏性 |   文件扩展名是否与原文件一致   |    是    |
|  文件大小一致性  | 替换文件的大小是否与原文件一致 |    否    |
|   文件可执行性   |    反制文件是否可以正常执行    |    是    |

上传到 C2 服务器的被窃取文件，在攻击者主机中运行的 Cobalt Strike 客户端界面中可展示查看，展示了文件名、文件路径、扩展名、创建时间、文件大小。经过分析验证，除了文件大小为替换后的大小，文件日期为 C2 服务器创建文件日期不作为评估指标外，其余信息均和原被窃取文件保持一致，提高了隐蔽性。之后，模拟攻击者将被窃取文件从 C2 服务器下载至攻击者主机进行执行查看，文件替换后的新文件可以正常执行。可以基于文件扩展名生成不同的反制文件进行文件替换，以控制追踪攻击者。

文件替换反制展示如图所示，攻击者操作 Cobalt Strike 客户端下载机密文件 secret.txt，中间人检测到 HTTP POST 请求携带文件上传任务执行结果，进行文件替换反制，替换为反制文件 myfile.txt。反制文件传递到 C2 服务器存储，Cobalt Strike 客户端支持攻击者从 C2 服务器同步已下载文件，反制文件同步至攻击者主机后，攻击者成功执行了被替换文件，txt 文件也已被替换。基于本节实验，证明了文件替换这一加密流量中间人劫持解密后进行的反制动作的可行性，并具有较强的隐蔽性。

<img src="images\fiel替换演示3_01.png" alt="fiel替换演示3_01" />

## 小结

介绍了基于中间人攻击的加密 C2 通信响应技术，提出了一种创新的防御方法，利用中间人技术对 Cobalt Strike 和 Meterpreter 进行主动防御。通过对加密通信流量的劫持、解密与篡改，本文提出的技术能够有效应对基于 TLS 和自定义加密协议的恶意 C2 流量。
首先，分析了 Cobalt Strike 和 Meterpreter 的通信机制，并揭示了它们在加密认证实现中的脆弱性。通过中间人攻击，可以破解加密的流量，替换其中的公钥，获取会话密钥，从而在用户无感条件下实时解密并分析通信内容，并且阐述了中间人攻击后实施穿过多种网络伪装节点实现反制的文件替换方法。

通过模拟中间人攻击环境，评估了该方法的适用性和有效性，实验结果表明，所提方法在 Cobalt Strike 和 Meterpreter 的 HTTP、HTTPS 协议和多种 Payload类型下能有效解密流量并对流量进行编辑修改，分析了不适用执行中间人攻击的 C2 工具配置，并展示了对加密 C2 通信信道进行中间人攻击的效果，保护网络安全和支撑研判分析。最后，本章展示了文件替换反制技术的隐蔽性和有效性，在攻击者下载文件的过程中，成功替换文件，仅文件大小展示改变，验证了该方法的实际应用隐蔽效果。