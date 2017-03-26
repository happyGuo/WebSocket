<?php
class User
{
    public $id;
    public $socket;
    public $handshake;
}

class WebSocket{
    public $master;  
    public $sockets = array(); 
    public $users = array();

    function __construct($address, $port){
        // 建立一个 socket 套接字 AF_INET是必须是一个四点分法的 IP 地址 
        //如果套接字是 AF_UNIX 族，那么 address 是 Unix 套接字一部分（例如 /tmp/my.sock
        $this->master = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)  
            or die("socket_create() failed");
        socket_set_option($this->master, SOL_SOCKET, SO_REUSEADDR, 1) 
            or die("socket_option() failed");
        socket_bind($this->master, $address, $port)                   
            or die("socket_bind() failed");
        socket_listen($this->master, 10)                              
            or die("socket_listen() failed");
        $this->sockets[] = $this->master;
    }

    public function run(){
         while(true) {
            $write = NULL;//$write是监听是否有客户端写数据，传入NULL是不关心是否有写变化。 
            $except = NULL;//$except是$sockets里面要被排除的元素，传入NULL是”监听”全部。
            $time = NULL;
            // 最后一个参数是超时时间
            // 如果为0：则立即结束
            // 如果为n>1: 则最多在n秒后结束，如遇某一个连接有新动态，则提前返回
            // 如果为null：如遇某一个连接有新动态，则返回 
            //接受数组的套接字,并等待他们改变状态  同步非阻塞的IO模型
            socket_select($this->sockets, $write, $except, $time);

            foreach ($this->sockets as $socket) {
                //连接主机的 client
                if ($socket == $this->master){
                    $client = socket_accept($this->master);
                    /*  此函数接受唯一参数，即前面socket_create创建的socket文件(句柄)。返回一个新的资源，或者FALSE。本函数将会通知socket_listen()，将会传入一个连接的socket资源。一旦成功建立socket连接，将会返回一个新的socket资源，用于通信。如果有多个socket在队列中，那么将会先处理第一个。关键就是这里：如果没有socket连接，那么本函数将会等待，直到有新socket进来。*/
                    if ($client === FALSE) {
                        //连接失败
                        echo "failed";
                        continue;
                    } else {
                        //有客户端连接过来
                        //http的第一次握手
                        $this->connect($client);
                       // echo "connect\n";
                    }
                } else {
                    //http的三次握手成功后发送数据，接收数据到buffer里
                    $bytes = @socket_recv($socket,$buffer,2048,0);
                    if($bytes == 0) $this->disconnect($socket);
                    $user = $this->getUserBySocket($socket);
                    // if (!$user) {
                    //     die('die');
                    // }
                    if (!$user->handshake) {
                        // 如果没有握手，先握手回应
                        $this->doHandShake($user, $buffer);
                       // echo "handshake\n";
                       //  echo $buffer;
                        /*GET / HTTP/1.1
                        Host: localhost:9000
                        Connection: Upgrade
                        Pragma: no-cache
                        Cache-Control: no-cache
                        Upgrade: websocket
                        Origin: http://m.lashou.com
                        Sec-WebSocket-Version: 13
                        User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36
                        Accept-Encoding: gzip, deflate, sdch
                        Accept-Language: zh-CN,zh;q=0.8
                        Sec-WebSocket-Key: F0hWIB9cCaJ9WGWZXq+wbg==
                        Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits*/
                        
                    } else {
                        // 如果已经握手，直接接受数据，并处理
                        $buffer = $this->process($user,$buffer);
                        echo $buffer;
                    }
                }
            }
        }
    }

    //简单返回一个消息
    protected function process($user, $msg)
    {
        $msg = $this->decode($user->socket,$msg);
    
        $this->send($user->socket, $msg);
    }   
    //有用户连接过来
    public function connect($clientSocket)
    {
        $user = new User();
        $user->id = uniqid();
        $user->socket = $clientSocket;
        array_push($this->users,$user);
        array_push($this->sockets,$clientSocket);
    }

    //断开连接
    public function disconnect($clientSocket)
    {
        $found = null;
        $n = count($this->users);
        for($i = 0; $i<$n; $i++)
        {
            if($this->users[$i]->socket == $clientSocket)
            { 
                $found = $i;
                break;
            }
        }
        $index = array_search($clientSocket,$this->sockets);
        
        if(!is_null($found))
        { 
            array_splice($this->users, $found, 1);
            array_splice($this->sockets, $index, 1); 
            
            socket_close($clientSocket);
        }
    }
    //获得连接的用户
    private function getUserBySocket($socket)
    {
        $found=null;
        foreach($this->users as $user)
        {
            if ($user->socket == $socket)
            {
                $found = $user;
                break;
            }
        }
        return $found;
    }

    //获得key
    public function getKey($req) {
        $key = null;
           if (preg_match("/Sec-WebSocket-Key: (.*)\r\n/", $req, $match)) {
            $key = $match[1];
           }
        return $key;
    }
    //加密key
    public function encry($req){
        $key = $this->getKey($req);
        //（GUID，[RFC4122]）标识：258EAFA5-E914-47DA-95CA-C5AB0DC85B11
        //此值不大可能被不明白WebSocket协议的网络终端使用
        $mask = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        return base64_encode(sha1($key.$mask, true));
   }

    public function dohandshake($user, $req){
        // 获取加密key
        $acceptKey = $this->encry($req);
        $upgrade = "HTTP/1.1 101 Switching Protocols\r\n" .
                   "Upgrade: websocket\r\n" .
                   "Connection: Upgrade\r\n" .
                   "Sec-WebSocket-Accept: " . $acceptKey . "\r\n\r\n";//必须以两个回车结尾

        // 写入socket
        socket_write($user->socket,$upgrade, strlen($upgrade));
        // 标记握手已经成功，下次接受数据采用数据帧格式
        $user->handshake = true;
   }

    // 解析数据帧
    protected function decode($clientSocket, $msg="")
    { 
        //https://github.com/wen866595/open-doc/blob/master/rfc/RFC6455-cn.md  --基本的帧协议
        $opcode = ord(substr($msg, 0, 1)) & 0x0F;
        $payloadlen = ord(substr($msg, 1, 1)) & 0x7F;//有效载荷
        $ismask = (ord(substr($msg, 1, 1)) & 0x80) >> 7;
        $maskkey = null;
        $oridata = null;
        $decodedata = null;
    
        if ($ismask != 1 || $opcode == 0x8) 
        {
            $this->disconnect($clientSocket);
            return null;
        }
        
       
        if ($payloadlen <= 125 && $payloadlen >= 0)
        {
            $maskkey = substr($msg, 2, 4);
            $oridata = substr($msg, 6);
        }
        else if ($payloadlen == 126)
        {
            $maskkey = substr($msg, 4, 4);
            $oridata = substr($msg, 8);
        }
        else if ($payloadlen == 127)
        {
            $maskkey = substr($msg, 10, 4);
            $oridata = substr($msg, 14);
        }
        $len = strlen($oridata);
        for($i = 0; $i < $len; $i++)  
        {
            $decodedata .= $oridata[$i] ^ $maskkey[$i % 4];
        }       
        return $decodedata; 
    }


    // 返回帧信息处理
    public function frame($s) {
        //\x81文本帧 
        $a = str_split($s, 125);
        if (count($a) == 1) {
            return "\x81" . chr(strlen($a[0])) . $a[0];
        }
        $ns = "";
        foreach ($a as $o) {
            $ns .= "\x81" . chr(strlen($o)) . $o;
        }
        return $ns;
    }

    // 返回数据
    public function send($client, $msg){
        $msg = $this->frame($msg);
        socket_write($client, $msg, strlen($msg));
    }
}

$ws = new WebSocket('localhost', 9000);
$ws->run();
