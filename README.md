# Deauth
Deauth attack



1. **Disassociation 패킷:**
    
    - **목적:** 클라이언트가 자발적으로 무선 네트워크를 떠날 때 사용됩니다.
    - **동작:** 클라이언트가 무선 네트워크를 떠나고자 할 때 AP(액세스 포인트)에게 알리기 위해 사용됩니다. 즉, 클라이언트가 네트워크를 나가고자 할 때 클라이언트가 AP에게 알리는 것입니다.
2. **Deauthentication 패킷:**
    
    - **목적:** 무선 네트워크에서 클라이언트를 강제로 로그아웃시키고자 할 때 사용됩니다.
    - **동작:** AP가 클라이언트를 무선 네트워크에서 로그아웃시키기 위해 사용됩니다. 이는 AP가 클라이언트에 대해 인증을 취소하고, 클라이언트가 네트워크에 접근할 수 없도록 하는 것입니다.

요약하면, "Disassociation" 패킷은 클라이언트가 자발적으로 네트워크를 떠날 때 사용되고, "Deauthentication" 패킷은 네트워크에서 클라이언트를 강제로 로그아웃시키기 위해 사용됩니다.


1. **Disassociation 패킷:**
    
    - `SRC` 주소 (Source Address): Disassociation 패킷을 보내는 클라이언트(또는 스테이션)의 MAC 주소입니다. 즉, 네트워크를 떠날 것을 요청하는 클라이언트의 주소를 나타냅니다.
    - `DST` 주소 (Destination Address): 이 패킷이 전송되는 곳, 즉 AP(액세스 포인트)의 MAC 주소입니다. Disassociation 패킷은 클라이언트가 AP에게 떠날 것임을 알리기 위해 사용되므로, 이 주소는 AP를 가리킵니다.
2. **Deauthentication 패킷:**
    
    - `SRC` 주소 (Source Address): Deauthentication 패킷을 보내는 기기의 MAC 주소입니다. 따라서, 로그아웃을 요청한 기기의 주소를 나타냅니다.
    - `DST` 주소 (Destination Address): 이 패킷이 전송되는 곳, 즉 Deauthentication을 수신하는 대상(클라이언트 또는 AP)의 MAC 주소입니다. Deauthentication 패킷은 로그아웃을 수신하는 대상을 가리킵니다.

요약하면, `SRC` 주소는 패킷을 보내는 기기의 주소를 나타내고, `DST` 주소는 패킷이 전송되는 대상의 주소를 나타냅니다.