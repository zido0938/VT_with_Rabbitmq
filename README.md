# Local Backup Solution using VirusTotal OpenAPI and Rabbitmq
<br/><br/><br/>
# [Build Environment]
<br/><br/>
Ubuntu 22.04
<br/><br/><br/>
# [Prerequisites]
<br/><br/>
1.OpenSSL Library Install
<br/><br/>
* sudo apt-get install libssl-dev 
<br/><br/>
2.Boost Library Install
<br/><br/>
* sudo apt update
* sudo apt install libboost-all-dev
<br/><br/>
<br/><br/>
3.nlohmann-json3 Install
<br/><br/>
* sudo apt-get install nlohmann-json3-dev
<br/><br/>
<br/><br/>
4.Cmake Library Install (for Rabbitmq-c, SimpleAmqpClient Library)
<br/><br/>
* sudo apt-get install cmake
<br/><br/>
<br/><br/>
5.Rabbitmq-c Library Install
<br/><br/>
* git clone https://github.com/alanxz/rabbitmq-c (Stable Version: https://github.com/alanxz/rabbitmq-c/releases/latest)
<br/><br/>
* move to folder rabbitmq-c
<br/><br/>
* mkdir build && cd build
<br/><br/>
* cmake ..
<br/><br/>
% Build Error가 뜰시 다음과 같이 바꿔주시면 됩니다. CmakeList.txt 에서 모든 rabbitmq::rabbitmq->rabbitmq로변경
<br/><br/>
<br/><br/>
6.Rabbitmq build with Vckpg
<br/><br/>
* git clone https://github.com/Microsoft/vcpkg.git
* cd vcpkg
* ./bootstrap-vcpkg.sh
* ./vcpkg integrate install
* sudo apt-get install build-essential
* ./vcpkg install librabbitmq
<br/><br/>
<br/><br/>
7.SimpleAmqpClient Library Install
<br/><br/>
* git clone https://github.com/alanxz/SimpleAmqpClient
<br/><br/>
% pkg -s libboost-dev | grep "Version" *Version must be over 1.4
<br/><br/>
* mkdir simpleamqpclient-build
* cd simpleamqpclient build
* cmake ..
* export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
<br/><br/>
<br/><br/>
8.Installing Rabbitmq Server
<br/><br/>
* sudo apt install rabbitmq-server
<br/><br/>
* sudo apt list --installed rabbitmq-server
<br/><br/>
<br/><br/>
9.Checking Rabbitmq server
<br/><br/>
* sudo systemctl status rabbitmq-server
<br/><br/>
* sudo rabbitmq-plugins enable rabbitmq_management(Installing GUI plugin)
<br/><br/>
# [Rabbitmq Server GUI] 
<br/><br/>
http://localhost:15672/ 아이디: Guest 비밀번호: Guest Port 15672
<br/><br/>
To start with python3 interface you should install tkinter by below 
<br/><br/>
1. sudo apt install -y python3-pip
<br/><br/>   
2. sudo apt-get install python3-tk
<br/><br/>
