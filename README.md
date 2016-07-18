1. 내 ip, mac 주소 획득

2. gateway ip 주소 획득 (victim ip는 인자로 획득)

3. arp request 패킷을 방송때려서 victim ip와 gateway ip의 주소 획득

4. 감염 arp reply 패킷을 victim과 gateway에 전송

5. arp request 패킷을 날려서 감염이 됐는지 확인

