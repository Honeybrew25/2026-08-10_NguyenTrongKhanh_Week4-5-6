# Demo thực thi thật trên terminal

> Xem [README](../README.md) để cài môi trường trước khi chạy.

Terminal hiển thị từng bước để người xem dễ theo dõi. Nó không thay đổi quy
tắc an toàn hoặc tự phê duyệt yêu cầu. API key chỉ được đọc từ môi trường và
không được in ra màn hình.

## Khởi động

```bash
docker compose down --remove-orphans
docker compose up --build --detach --wait --wait-timeout 180
python -m project_sentinel preflight --execute
python -m project_sentinel demo --provider deterministic --execute --format human
```

Chỉ dùng `--verbose` khi cần xem mã của quy tắc và yêu cầu.

Mỗi tình huống có tám bước: nhận kết quả quét, chuẩn hóa, phân tích, tạo đề
xuất, phê duyệt, gửi qua cổng Envoy, kiểm tra phản hồi và tạo báo cáo.

## Chọn kiểu hiển thị

`--format auto` tự chọn kiểu phù hợp: terminal dùng bản dễ đọc, còn kết quả
chuyển sang tệp dùng JSON. Có thể chọn trực tiếp:

```bash
# Trình bày trực tiếp
python -m project_sentinel demo --provider deterministic --execute --format human

# Dùng trong script hoặc CI
python -m project_sentinel demo --provider deterministic --format json
```

## Nếu cổng Envoy chưa sẵn sàng

Mã `gateway_preflight_timeout` có nghĩa là hệ thống chưa gửi yêu cầu kiểm thử.
Kiểm tra theo thứ tự sau:

```bash
docker compose ps
curl http://127.0.0.1:8080/health
docker compose logs --no-color --tail 200 envoy authz-service api
```

`/health` phải trả về HTTP `200`. Nếu vừa mở Docker, chờ các dịch vụ chuyển
sang `healthy`, rồi chạy lại:

```bash
python -m project_sentinel preflight --execute
```

## Kết thúc

```bash
docker compose down --remove-orphans
docker compose ps --all
```
