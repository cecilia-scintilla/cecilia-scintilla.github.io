---
layout: post
title: Bugku CTF - 眼见非实 Writeup
date: 2026-10-05 20:00:00 +0800
categories: CTF
---

Bugku CTF - 眼见非实 Writeup

一、题目信息

- 题型：MISC（杂项）
- 题目：眼见非实
- 考点：**文件头识别（不看后缀看内容）**、伪装文件、OOXML 文档结构、**Word 隐藏文字**

二、flag 和它的藏法

- 它藏在解压后的 `word/document.xml` 里，**并且被 Word 的"隐藏文字"属性包裹着**：

```xml
<w:r w:rsidRPr="002B3D8D">
  <w:rPr><w:vanish/></w:rPr>          <!-- ★ 这个标签让文字"隐形" -->
  <w:t>flag{F1@g}</w:t>
</w:r>
```

- 也就是说这题的"眼见非实"有**两层含义**：

```text
第一层：后缀是假的  —— 看着是 .docx，其实是 zip
第二层：内容也不可见 —— 就算正常打开 Word，flag 也是隐形文字，看不见
```

- 所以哪怕你把它当成正常 Word 文档打开、也没报错，照样看不到 flag —— 必须解开 zip 去看 XML 源码（或者开启 Word 的"显示隐藏文字"）。

三、题目分析

- 下载附件，得到一个 **.docx 文件**。双击打开的话 Word 会报错或显示异常 —— 这是第一个可疑信号。
- "眼见非实"这个题目名就是核心提示：**你看到的（后缀名）不一定是真的**。
- 判断真实类型的方法：**看文件头（magic number），不看后缀**。用记事本打开这个 docx，开头是这样的：

```text
50 4B 03 04     ->  这是 "PK.."，ZIP 压缩包的文件头！
```

- 而正常 Word 文档（.docx）本身也是 zip 格式，但如果这个文件打不开、又只有 `PK` 头却没有正常的 docx 结构，就说明它**其实是个被改了后缀的压缩包**。
- 所以解法很直接：**当成 zip 处理，解开找 flag**。

四、解题步骤

**第 0 步：先学会判断真实文件类型**

这是本题真正要考的技能。三种方式任选：

```powershell
# ① 用 file 命令（Git Bash 里能直接用）
file 眼见非实.docx
# 输出: Zip archive data, at least v2.0 to extract

# ② 用 PowerShell 看前 8 个字节的十六进制（Windows 自带，不用装东西）
(Get-Content 眼见非实.docx -Encoding Byte -TotalCount 8 | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
# 输出: 50 4B 03 04 14 00 00 00   -> PK.. 就是 ZIP

# ③ 用 Python（跨平台最稳，任何 PowerShell 版本都能跑）
python -c "print(open('眼见非实.docx','rb').read(4).hex(' ').upper())"
# 输出: 50 4B 03 04

# ④ 最简单：用记事本打开，开头两个字符能看到 "PK"
```

> ⚠️ 注意：`Format-Hex` 这个命令看起来很合适，但它的 `-Count` / `-Head` 参数在 **Windows PowerShell 5.1** 里**不存在**（只有 PowerShell 7+ 支持），直接用会报参数错误。所以上面给的是 `Get-Content -Encoding Byte` 写法，5.1 和 7 都能用。

> 记住这个表（CTF 高频）：
> `50 4B 03 04` = ZIP（docx/xlsx/pptx 也是这个头）｜`89 50 4E 47` = PNG｜`FF D8 FF` = JPEG｜`25 50 44 46` = PDF｜`4D 5A` = Windows exe｜`7F 45 4C 46` = Linux 程序

**第 1 步：把后缀改成 zip，解压**

```text
眼见非实.docx  →  重命名为  眼见非实.zip  →  解压
```

**第 2 步：在解压出来的文件里找 flag**

解压后会得到一堆文件夹和 XML 文件，这是 OOXML 文档（docx）的内部结构：

```text
[Content_Types].xml
_rels/.rels
word/
  ├── document.xml      ← ★ flag 通常在这里（正文内容）
  ├── styles.xml
  └── ...其它 xml
docProps/
```

- **优先看 `word/document.xml`**（本题的 flag 就在这里），flag 就写在正文里；
- 看不到就挨个 XML 用记事本打开搜 `flag`，或者用搜索工具在**整个解压目录**里搜。

```powershell
# 在解压出来的目录里全局搜（Windows PowerShell）
Select-String -Path .\解压目录\* -Pattern "flag" -Recurse
```

本题 `word/document.xml` 里命中 flag 的那段代码：

```xml
<w:pPr><w:rPr><w:rFonts w:hint="eastAsia"/><w:vanish/></w:rPr></w:pPr>
<w:r w:rsidRPr="002B3D8D">
  <w:rPr><w:vanish/></w:rPr>
  <w:t>flag{F1@g}</w:t>          <!-- ★ 答案 -->
</w:r>
```

五、延伸知识：Word 的"隐藏文字"（<w:vanish/>）

本题的 flag 是**隐形**的，靠的就是 OOXML 里的 `<w:vanish/>` 标签。这个知识点很实用，展开说一下。

**① 什么是隐藏文字**

Word 支持把一段文字设为"隐藏"，效果是：**正常查看/打印时都看不见，但内容确实还在文档里**。

- 在 Word 里的操作：选中文字 → 右键"字体" → 勾选 **"隐藏"**
- 对应的 XML 标记就是 `<w:vanish/>`（vanish = 消失）

**② 怎么让它现形（两种办法）**

```text
办法 A（在 Word 里显示隐藏文字）：
    Word → 文件 → 选项 → 显示 → 勾选"隐藏文字" → 确定
    这时隐藏的 flag 就会带着虚线下划线显示出来

办法 B（推荐，绕开 Word 直接看源码）：
    按前面说的把 docx 当 zip 解开，直接读 word/document.xml
    —— 这样任何隐藏、任何格式都藏不住
```

**③ 为什么 CTF 里要优先用"办法 B"**

因为文档类隐写**不止隐藏文字一种**，还有：

```text
· 隐藏文字 <w:vanish/>        —— 本题
· 白色字体（白底白字，看不见但存在）
· 字号设为 1（小到看不见）
· 文字被放在文本框/页眉页脚/批注里
· 文档属性（docProps/core.xml 的标题、作者字段）
· 文件尾部附加数据、或用 zip 的"注释"字段藏信息
```

**直接看 XML 源码可以一次性忽略所有这些"障眼法"** —— 反正内容是明文存在里面的。这就是为什么做文档类隐写题，第一选择永远是"解开 zip 看 XML"，而不是在 Word 界面里折腾显示设置。

六、为什么要考"改后缀"这件事

- 文件后缀只是**文件名的一部分**，操作系统靠它决定"用什么软件打开"，但**它不决定文件里到底是什么内容**。
- 服务器/程序判断文件类型时，**必须看文件头**（这也是为什么很多上传漏洞的绕过方式就是"改后缀 + 保留真实文件头"）。
- 现实生活中同理：黑客常把恶意 exe 伪装成 .jpg、.pdf 发给你，**只看后缀就会中招**。

七、总结

- **本题核心技能：不要相信后缀名，要看文件头。** 拿到任何 CTF 附件，第一步都应该是用 `file` 命令（或看十六进制头部）确认真实类型。
- **本题第二层考点：隐藏文字。** 就算文件打开正常，也不代表"看到的全部"——文档里可能有隐藏文字、白字、超小字号、藏在属性里的内容。**直接读源码（解开 zip 看 XML）是最可靠的破解方式。**
- 常见"伪装"套路，遇到打不开或看着正常的文件都可以挨个试：

```text
① 后缀与内容不符     -> 改后缀（本题：docx 其实是 zip）
② 压缩包套压缩包     -> 一层层解（如 linux 那题：zip → tar.gz → 磁盘镜像）
③ 文件尾部附加数据   -> strings / 十六进制看末尾（如"这是一张单纯的图片"）
④ 图片尺寸被改       -> 改宽高（如"隐写"那题）
⑤ 扩展名被改成图片   -> 改回 zip 后解压，或直接 binwalk
⑥ 文档里有隐藏文字/白字 -> 解开 docx 看 word/document.xml（本题）
```

- 顺带记住 OOXML 结构（docx/xlsx/pptx 都是 zip）：

```text
word/document.xml        Word 正文（本题 flag 在这里）
word/header*.xml         页眉
word/footer*.xml         页脚
word/comments.xml        批注
xl/sharedStrings.xml     Excel 的文本内容
ppt/slides/slide*.xml    PPT 各页内容
docProps/core.xml        文档属性（标题、作者、创建时间）
```

很多"文档类"隐写题都是从这些文件里翻出 flag 的。
