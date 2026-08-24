# Tóm tắt lần phân tích Gemini cho mentor

## Thông tin lần chạy

- Ngày chạy: 2026-08-24.
- Provider thực tế: `gemini:gemini-3.5-flash-lite`.
- Đầu vào: `security-results/normalized-findings.json`.
- Kho kiến thức: `data/vulnerabilities.json`.
- Kết quả: 27 finding được gom thành 9 nhóm có nguồn.
- Đây là lượt gọi LLM thật, không phải provider `deterministic`.

## Kết quả dễ đọc

| Nhóm | Mức độ | Số finding | Giải thích của Gemini |
|---|---|---:|---|
| `bandit:B310` | Medium | 2 | Công cụ cảnh báo mã nguồn có thể đang sử dụng hàm mở URL với các scheme chưa được kiểm soát chặt chẽ, dẫn đến khả năng xảy ra yêu cầu phía máy chủ nếu đầu vào thay đổi được. |
| `bandit:B101` | Low | 14 | Công cụ phát hiện việc sử dụng câu lệnh `assert` trong mã nguồn, có thể bị loại bỏ khi biên dịch mã bytecode tối ưu. |
| `bandit:B105` | Low | 1 | Công cụ cảnh báo có thể có chuỗi thông tin nhạy cảm hoặc mật khẩu được gán cứng trong mã nguồn. |
| `bandit:B404` | Low | 2 | Công cụ cảnh báo sự hiện diện của module `subprocess`, có thể tiềm ẩn rủi ro nếu tham gia thực thi lệnh hệ điều hành từ dữ liệu không tin cậy. |
| `bandit:B603` | Low | 2 | Công cụ cảnh báo lệnh gọi `subprocess` có thể thực thi dữ liệu đầu vào chưa được kiểm tra đầy đủ. |
| `zap:10021` | Low | 1 | Công cụ quét phát hiện phản hồi HTTP thiếu header `X-Content-Type-Options`, có thể khiến trình duyệt đoán kiểu nội dung không an toàn. |
| `zap:90004-1` | Low | 1 | Công cụ quét phát hiện thiếu header `Cross-Origin-Resource-Policy`, có thể làm giảm khả năng bảo vệ tài nguyên trước một số kỹ thuật tấn công phía client. |
| `zap:10049-1` | Informational | 3 | Công cụ quét ghi nhận nội dung phản hồi không được lưu trữ bởi các thành phần bộ nhớ đệm trung gian. |
| `zap:10049-3` | Informational | 1 | Công cụ quét ghi nhận nội dung phản hồi có thể được lưu trữ và chia sẻ bởi các thành phần bộ nhớ đệm. |

## Cách đọc các file

- `security-analysis.jsonl`: bản chuẩn cho chương trình; mỗi dòng là một nhóm.
- `security-analysis.pretty.json`: cùng dữ liệu nhưng được thụt dòng và gom
  thành mảng JSON để người đọc mở trực tiếp trong IDE.
- File này: bản tóm tắt ngắn để trình bày với mentor.

Finding của scanner chỉ là tín hiệu cần xác minh, chưa chứng minh có lỗ hổng có
thể khai thác. Các bước xác minh, khắc phục, vị trí và nguồn đầy đủ nằm trong
hai file JSON phía trên.
