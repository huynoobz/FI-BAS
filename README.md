# FI-BAS (In Dev)
Dự án phát triển giải pháp Mô phỏng Tấn công Vi phạm cho Tường lửa và Hệ thống Ngăn chặn Xâm nhập. Tên đầy đủ của giải pháp là Breach and Attack Simulation for Firewall and Intrusion prevent system (FI-BAS).

## Server
- Hoạt động như 1 C2 server, gửi các lệnh đến agent để agent thực thi và phản hồi về server. 
- Mô phỏng các tấn công với mục tiêu là agent.

## Agent
- Hoạt động như zombie trong ngữ cảnh C&C, nhận các lệnh từ server, thực thi và phản hồi về server.
- Phối hợp với server để thực hiện mô phỏng, hỗ trợ đánh giá mô phỏng, dọn dẹp (nếu có).

## Installation
- Với server, chạy server_setup.py trước khi chạy server.py
- Với agent, chạy agent_setup.py trước khi chạy agent.py

## Môi trường thử nghiệm lí tưởng
Server <---> Firewall <---> IPS <---> Agent

## Triển khai server - agent
- Bước 1: Chạy server.py trên server
- Bước 2: Chạy agent.py trên agent
- Bước 3: Nhập các đầu vào cần thiết cho agent (các giá trị mà server.py đưa ra mà hình)
