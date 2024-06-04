How to build and execute

1:mkdir build
2:cmake ..
3:make
4:cd ..
5:python3 main.py

기본 API_KEY: a38859e8e395fa859d1fde4ed881c2aee19eaedd043dbc89b1162feb27b107bc


이쪽 사용자가 A라고 가정
Send는 AB큐를 , Receieve는 BA큐를 사용한다.


기본적으로 

계정: (try1, 1234)
IP: 166.104.245.156
vhost: /1
port: 5672

사용중이다. 사용시 적절하게 수정하여 사용(msqueue_send.cpp와 msqueue_receive.cpp의 코드를 수정)

Send Queue 사용시에는 보낼 파일만 정확하게 지정해주면되고(File버튼으로) 
Receive Queue 사용시에는 받을 폴더 경로만 정확하게 지정해주면된다(Select Path버튼으로)
