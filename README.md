# Báo cáo phân tích và phát hiện: kỹ thuật LSASS Memory Dumping

> **Mã kỹ thuật MITRE ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory)
> **Mục tiêu:** Kiểm thử khả năng phát hiện hành vi trích xuất bộ nhớ của tiến trình `lsass.exe`.

## 1. Tiến trình LSASS
lsass.exe là một tiến trình của Windows chịu trách nhiệm quản lý chính sách bảo mật cho hệ điều hành. Ví dụ, khi user đăng nhập vào tài khoản người dùng hoặc máy chủ Windows, lsass.exe sẽ xác minh tên đăng nhập và mật khẩu. Nếu tắt lsass.exe, user có thể sẽ bị đăng xuất khỏi Windows. lsass.exe cũng ghi vào nhật ký bảo mật Windows, vì vậy user có thể tìm kiếm ở đó các lần xác thực không thành công cùng với các vấn đề khác liên quan đến chính sách bảo mật.
![alt text](./images/image-4.png)

## 2. Trích xuất thông tin đăng nhập từ tiến trình LSASS

### Bản chất của cuộc tấn công
Ý nghĩa: Khi người dùng đăng nhập vào Windows, hệ thống sẽ tạo ra và lưu trữ nhiều loại thông tin xác thực (như mật khẩu dạng cleartext, hàm băm NTLM, vé Kerberos) ngay trong bộ nhớ RAM của tiến trình lsass.exe. Kẻ tấn công (đã có quyền Administrator hoặc SYSTEM) sẽ nhắm vào bộ nhớ này để đánh cắp thông tin.

Mục đích: Khi có được các thông tin này, kẻ tấn công sẽ thực hiện di chuyển ngang, dùng tài khoản vừa lấy cắp để lây lan sang các máy tính khác trong cùng mạng nội bộ mà không cần phải bẻ khóa mật khẩu.

### Giả định kịch bản và thiết lập môi trường 

Trong khuôn khổ của bài nghiên cứu này, tính năng Real-time Protection của Windows Defender trên máy nạn nhân đã được cố ý vô hiệu hóa.

Lý do:

Mục tiêu nghiên cứu: trọng tâm của báo cáo là phân tích hành vi sinh log của hệ điều hành (thông qua Sysmon) và kiểm thử năng lực phát hiện của hệ thống SIEM/Wazuh, chứ không phải đánh giá khả năng phòng ngừa của các phần mềm Antivirus.

Tính thực tiễn của kịch bản: các công cụ và kỹ thuật như ProcDump hiện nay đã bị window defender nhận diện rất tốt. Tuy nhiên, trong các cuộc tấn công có chủ đích, khi kẻ tấn công đã giành được đặc quyền quản trị (Administrator/SYSTEM), kẻ tấn công thường sử dụng các kỹ thuật để vô hiệu hóa hoặc làm mù hệ thống antivirus. Việc tắt defender giúp mô phỏng chính xác giai đoạn sau xâm nhập khi lớp phòng thủ đầu tiên đã bị vô hiệu hóa, buộc tổ chức phải dựa vào lớp phòng thủ tiếp theo là giám sát log hệ thống.


## 3. Mô phỏng kỹ thuật tấn công
Để kiểm thử khả năng phát hiện của Wazuh, quá trình trích xuất bộ nhớ LSASS được thực hiện thông qua kỹ thuật lạm dụng thư viện comsvcs.dll. Kỹ thuật này không cần tải thêm file thực thi lạ nào xuống máy nạn nhân, mà sử dụng hàm MiniDump có sẵn của Windows:

### Tìm PID của lsass.exe
```PowerShell
Get-Process lsass
```

### Thực thi hàm dump bộ nhớ
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump PID C:\Windows\Temp\lsass_comsvcs.dmp full

![alt text](./images/image-5.png)

Sau khi lấy được file .dmp, kẻ tấn công sẽ tải file này về máy tính cá nhân của kẻ tấn công. Tại đây, kẻ tấn công dùng Mimikatz chạy các lệnh như sekurlsa::Minidump (nạp file dump) và sekurlsa::logonPasswords (lấy mật khẩu).

![alt text](./images/image-10.png)

Sau khi có mật khẩu dưới dạng hash thì kẻ tấn công có thể dùng johntheripper để đoán 

![alt text](./images/image.png)

![alt text](./images/image-1.png)

Vậy trong trường hợp này kẻ tấn công đã đoán được mật khẩu là "password"

## 4. Phân tích Dấu hiệu nhận biết 
Hệ thống ghi log Sysmon được sử dụng để bắt các sự kiện ở mức độ hệ thống. Qua quá trình mô phỏng, ba loại Event ID chính đã được ghi nhận:

### 4.1. Sysmon Event ID 1: Process Creation 
Sự kiện này bắt được dòng lệnh gọi rundll32.exe nạp thư viện comsvcs.dll cùng từ khóa MiniDump.

![alt text](./images/image-6.png)

### 4.2. Sysmon Event ID 10: Process Access 
Đây là dấu hiệu đáng tin cậy vì nó bắt đúng hành vi chạm vào bộ nhớ LSASS, bất kể kẻ tấn công dùng công cụ gì hay đổi tên file ra sao.

![alt text](./images/image-7.png)
TargetImage: C:\Windows\System32\lsass.exe

GrantedAccess: Cấp quyền đọc bộ nhớ, thường xuất hiện với các mã Hex như 0x1fffff (full access) hoặc 0x1010, 0x1410.


### 4.3. Sysmon Event ID 11: File Create

![alt text](./images/image-8.png)


## 5. Xây dựng luật phát hiện trên Wazuh

Dựa trên các dấu hiệu phân tích từ Sysmon Event ID 10, một custom rule được tạo trên Wazuh để cảnh báo tự động khi có tiến trình khả nghi truy cập vào LSASS.

```XML
<group name="windows, sysmon, lsass_access,">
  <rule id="100050" level="12">
    <if_group>sysmon_event_10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
    <field name="win.eventdata.grantedAccess" type="pcre2">0x1fffff|0x1010|0x1410</field>
    <description>Phát hiện hành vi truy cập bộ nhớ LSASS đáng ngờ (Khả năng Dump Credential)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
</group>

```

Sau khi mô phỏng tấn công lại thì đã bắt được hành vi lsass trên wazuh
![alt text](./images/image-9.png)

## 6. Kết luận và hướng đề xuất chống tấn công:
Bài báo cáo đã thực hiện mô phỏng thành công kỹ thuật OS Credential Dumping (T1003.001) và xây dựng được năng lực giám sát, phát hiện cảnh báo trên hệ thống Wazuh thông qua việc phân tích log Sysmon.

Do giới hạn của môi trường thực nghiệm (Lab cá nhân), hệ thống không được triển khai các phần mềm doanh nghiệp như hệ thống Antivirus (AV/EDR), công cụ sao lưu (Backup Agents) hay phần mềm giám sát (Monitor). Trong môi trường thực tế, các phần mềm hợp lệ này thường xuyên phải truy cập vào bộ nhớ lsass.exe để thực thi tác vụ, dẫn đến việc Rule 100050 có thể sinh ra một lượng lớn cảnh báo giả. 


### Đề xuất phòng chống

Để đối phó với kỹ thuật LSASS Memory Dumping (T1003.001) và giải quyết trọn vẹn bài toán bảo mật hệ thống, cần áp dụng chiến lược phòng thủ theo chiều sâu dựa trên khung tiêu chuẩn MITRE ATT&CK. Dưới đây là các biện pháp giảm thiểu cụ thể:

#### Bảo vệ toàn vẹn tiến trình và bộ nhớ
* **Privileged Process Integrity (M1025):** Kích hoạt tính năng Protected Process Light cho LSA trên Windows 8.1 và Windows Server 2012 R2 trở lên. Thiết lập này yêu cầu các tiến trình phải có chữ ký số hợp lệ từ Microsoft mới có thể tương tác hoặc đọc bộ nhớ của lsass.exe.
* **Credential Access Protection (M1043):**  Triển khai tính năng Windows Defender Credential Guard. Công nghệ này sử dụng tính năng ảo hóa dựa trên phần cứng để cô lập bộ nhớ chứa LSA secrets. Cần lưu ý giải pháp này yêu cầu phần cứng/firmware tương thích và không được bật sẵn theo mặc định.
* **Operating System Configuration (M1028):** 
  * Vô hiệu hóa xác thực WDigest (thông qua registry) để ngăn Windows lưu trữ mật khẩu dưới dạng cleartext trong bộ nhớ RAM.
  * Xem xét việc hạn chế hoặc vô hiệu hóa hoàn toàn giao thức NTLM trong môi trường domain nếu có thể, chuyển sang ưu tiên sử dụng Kerberos.

#### Ngăn chặn hành vi trên thiết bị đầu cuối
* **Behavior Prevention on Endpoint (M1040):** Bật các quy tắc Giảm thiểu bề mặt tấn công (Attack Surface Reduction - ASR) trên Windows 10/11. Cụ thể, quản trị viên cần kích hoạt rule "Block credential stealing from the Windows local security authority subsystem" để tự động chặn các hành vi khả nghi cố gắng trích xuất dữ liệu từ LSASS.

#### Quản lý đặc quyền và tài khoản 
* **Active Directory Configuration (M1015):** Đưa các tài khoản quản trị quan trọng vào nhóm bảo mật "Protected Users" trong Active Directory. Điều này giúp giới hạn việc hệ thống tự động lưu trữ thông tin xác thực cleartext của các user này trên máy trạm. Đồng thời, quản lý chặt chẽ danh sách kiểm soát truy cập đối với các quyền nhạy cảm như "Replicating Directory Changes All".
* **Privileged Account Management (M1026):** Không thêm các tài khoản domain (đặc biệt là tài khoản admin) vào nhóm Local Administrator trên các máy trạm trừ khi được kiểm soát cực kỳ gắt gao. Nên áp dụng mô hình phân cấp quản trị để giới hạn việc sử dụng tài khoản đặc quyền chéo giữa các hệ thống.
* **Password Policies (M1027):** Đảm bảo các tài khoản quản trị viên cục bộ có mật khẩu phức tạp và hoàn toàn duy nhất cho từng máy (khuyến nghị sử dụng giải pháp như Microsoft LAPS).
* **User Training (M1017):** Đào tạo người dùng và quản trị viên không sử dụng chung một mật khẩu cho nhiều tài khoản và hệ thống khác nhau để giới hạn mức độ ảnh hưởng nếu một tài khoản bị lộ lọt.

#### Tối ưu hóa hệ thống giám sát 
Để khắc phục hạn chế về cảnh báo giả (False Positives) do Rule 100050 sinh ra (đã đề cập trong phần kết luận), hệ thống cần được tinh chỉnh lại:
* **Xây dựng Baseline:** Giám sát hệ thống trong trạng thái bình thường để lập danh sách trắng các tiến trình hợp lệ thường xuyên cần quyền truy cập LSASS (như Antivirus, công cụ Backup).
* **Nâng cấp Rule trên Wazuh:** Bổ sung điều kiện loại trừ. Cảnh báo sẽ chỉ kích hoạt nếu TargetImage là lsass.exe, GrantedAccess là mức quyền nguy hiểm, và SourceImage (tiến trình gọi) không nằm trong Whitelist đã được phê duyệt.