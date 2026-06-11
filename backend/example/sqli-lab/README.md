# SQLi Lab

这个目录对应一个本地 SQL 注入验证环境，服务代码在 [backend/cmd/sqli-lab/main.go](/Users/qwtd/WorkManageCode/trailblazer/backend/cmd/sqli-lab/main.go)。

## 启动

```bash
cd /Users/qwtd/WorkManageCode/trailblazer/backend
go run ./cmd/sqli-lab
```

默认监听 `http://127.0.0.1:18082`。也可以通过环境变量改端口：

```bash
SQLI_LAB_ADDR=:28082 go run ./cmd/sqli-lab
```

## 端点

### 1. error-based

`GET /api/sqli/error?user=...`

- 正常值返回 `200`
- 参数中包含单引号时返回 `500` 和典型 SQL 报错文本

示例：

```bash
curl 'http://127.0.0.1:18082/api/sqli/error?user=alice'
curl 'http://127.0.0.1:18082/api/sqli/error?user=%27'
```

### 2. boolean-based

`GET /api/sqli/boolean?user=...`

- baseline 和 `''` 返回相同业务结果
- `'` 返回不同业务结果

这个端点就是为了验证 `baseline -> "'" -> "''"` 的三点比较逻辑。

示例：

```bash
curl 'http://127.0.0.1:18082/api/sqli/boolean?user='
curl 'http://127.0.0.1:18082/api/sqli/boolean?user=%27'
curl 'http://127.0.0.1:18082/api/sqli/boolean?user=%27%27'
```

### 3. time-based

`GET /api/sqli/time?user=...`

- baseline 固定约 `150ms`
- 参数包含 `sleep`、`pg_sleep`、`waitfor` 时额外延迟约 `2200ms`

示例：

```bash
time curl 'http://127.0.0.1:18082/api/sqli/time?user=alice'
time curl 'http://127.0.0.1:18082/api/sqli/time?user=%27%20OR%20SLEEP(5)--'
```

### 4. false-positive

`GET /api/sqli/false-positive?user=...`

- 参数中带单引号时只返回通用 `400 invalid input`
- 这是专门用来验证“不要把普通参数校验失败当 SQLi”

示例：

```bash
curl -i 'http://127.0.0.1:18082/api/sqli/false-positive?user=%27'
```

### 5. dynamic

`GET /api/sqli/dynamic?user=...`

- baseline 和 `''` 都会带动态 `trace`
- `'` 返回错误
- 这个端点用于验证“结构等价”而不是死比全文

示例：

```bash
curl 'http://127.0.0.1:18082/api/sqli/dynamic?user='
curl 'http://127.0.0.1:18082/api/sqli/dynamic?user=%27%27'
curl 'http://127.0.0.1:18082/api/sqli/dynamic?user=%27'
```

## 用它验证当前检测器

如果你只想验证 `TestSQLInjection` 的效果，目标优先看这几个：

- `http://127.0.0.1:18082/api/sqli/error`
- `http://127.0.0.1:18082/api/sqli/boolean`
- `http://127.0.0.1:18082/api/sqli/time`
- `http://127.0.0.1:18082/api/sqli/false-positive`
- `http://127.0.0.1:18082/api/sqli/dynamic`

推荐先分别单打每个端点，确认哪种类型命中，再放进完整扫描流程。
