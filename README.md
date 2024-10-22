
# mini_rust_desk_id_server ID 服务器

## 简介

mini_rust_desk_id_server通过提供集合和信号服务，帮助 RustDesk 客户端实现初始连接设置。它协助建立直接连接，或者当由于网络限制无法建立 P2P 连接时，通过中继服务器路由。

#### 命令行参数

这里是一些可配置的命令行选项：

- `-p, --port=[NUMBER]`：设置 ID 服务器的监听端口，默认为 `21114`（如果未指定）。
  - 示例：`./mini_rust_desk_id_server --port=21114`

- `-s, --serial=[NUMBER]`：设置配置更新序列号，默认为 `0`。
  - 示例：`./mini_rust_desk_id_server --serial=100`

- `-R, --rendezvous-servers=[HOSTS]`：指定其他集合服务器，用逗号分隔。
  - 示例：`./mini_rust_desk_id_server --rendezvous-servers=server1,server2`

- `-r, --relay-servers=[HOST]`：指定默认的中继服务器，用逗号分隔。
  - 示例：`./mini_rust_desk_id_server --relay-servers=relay1,relay2`

- `-k, --key=[KEY]`：限制只允许提供匹配密钥的客户端访问。
  - 示例：`./mini_rust_desk_id_server --key="your_secret_key"`

- `--mask=[MASK]`：确定连接是否来自局域网，例如 192.168.0.0/16。
  - 示例：`./mini_rust_desk_id_server  --mask="192.168.0.0/16"`