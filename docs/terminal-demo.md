# Demo thực thi thật trên terminal

> Xem [documentation hub](../README.md) để cài môi trường trước khi chạy.

## Mục đích

Chế độ terminal hướng dẫn người xem qua từng bước nhưng không thay đổi policy,
quyết định phê duyệt hoặc cách request đi qua Gateway. API key chỉ được runtime
nạp từ môi trường; terminal không in giá trị này.

## Khởi động

```bash
docker compose down --remove-orphans
docker compose up --build --detach --wait --wait-timeout 180
python -m project_sentinel preflight --execute
python -m project_sentinel demo --provider deterministic --execute --format human
```

Nếu terminal không hiển thị màu phù hợp, thêm `--no-color`. Dùng `--verbose`
chỉ khi cần xem đầy đủ policy hash và request fingerprint.

Mỗi tình huống có cùng tám bước:

1. nhận kết quả quét;
2. chuẩn hóa cảnh báo;
3. phân tích;
4. tạo đề xuất;
5. phê duyệt;
6. gửi qua Gateway;
7. kiểm tra response;
8. tạo báo cáo.

## Output

`--format auto` là mặc định: terminal tương tác dùng giao diện dễ đọc, còn khi
redirect output thì giữ JSON. Có thể chọn rõ ràng:

```bash
# Trình bày trực tiếp
python -m project_sentinel demo --provider deterministic --execute --format human

# Script, CI hoặc xử lý bằng công cụ khác
python -m project_sentinel demo --provider deterministic --format json
```

## Khi Gateway chưa sẵn sàng

Lệnh demo kiểm tra Gateway một lần trước khi quét và chạy các tình huống. Nếu
thấy mã `gateway_preflight_timeout`, chưa có request kiểm thử nào được gửi. Kiểm
tra theo thứ tự:

```bash
docker compose ps
curl http://127.0.0.1:8080/health
docker compose logs --no-color --tail 200 envoy authz-service api
```

Kết quả health đúng là HTTP `200`. Nếu vừa khởi động Docker, chờ các service có
trạng thái `healthy` rồi chạy lại
`python -m project_sentinel preflight --execute`.

## Kết thúc

```bash
docker compose down --remove-orphans
docker compose ps --all
```
