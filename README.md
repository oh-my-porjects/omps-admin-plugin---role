# 角色公共模块 (role)

## Features
提供角色树、权限点、角色权限分配、角色状态管理与权限校验能力。

## Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | /api/role/hello | 返回模块名称和版本 | public |
| POST | /api/role/create | 创建角色并可绑定权限点 | public |
| GET | /api/role/list | 分页查询角色列表 | public |
| GET | /api/role/detail | 查询角色详情及已绑定权限 | public |
| PUT | /api/role/update | 更新角色基础信息和层级 | public |
| GET | /api/role/children-tree | 查询角色及完整子角色树 | public |
| POST | /api/role/delete | 级联软删除角色及子角色 | public |
| POST | /api/role/disable | 禁用角色 | public |
| POST | /api/role/enable | 启用角色 | public |
| POST | /api/role/permission-create | 创建权限点 | public |
| GET | /api/role/permission-list | 分页查询权限点 | public |
| PUT | /api/role/assign-permissions | 覆盖分配角色权限点 | public |
| POST | /api/role/check-permission | 检查角色是否拥有权限点；`system.manage` 视为全权限 | public |
| POST | /api/role/admin/ping | 管理后台探活 | api_key |
| POST | /_internal/method-call/role | Runtime 内部方法调用入口 | api_key |
| POST | /_internal/scheduled-trigger/role | Runtime 内部手动触发定时任务 | api_key |
| POST | /_internal/selftest/role | 已废弃的内部自测入口 | api_key |

## Database

- `role_roles` — 存储角色树节点；关键字段为 `id`、`name`、`parent_id`、`status`、`description`、`deleted_at`，`id` 为主键，`parent_id` 外键指向自身并禁止自引用。
- `role_permissions` — 存储权限点；关键字段为 `id`、`code`、`name`、`description`，`code` 全局唯一。
- `role_role_permissions` — 存储角色与权限点绑定关系；关键字段为 `role_id`、`permission_id`，组合唯一，并通过外键级联清理。

## Design Notes

- 角色采用父子树表达管理范围，创建角色时会按当前后台账号上下文推导或校验父角色。
- 子角色权限必须是父角色权限子集，避免下级角色获得上级未授权的能力。
- 权限分配是覆盖式写入，并会阻止清理后导致子角色越权的操作。
- 删除为级联软删除，根角色和系统内置角色受保护，状态变更与删除会通过 `ctx.Audit` 上报。
- 无数据库连接时使用内存存储兜底，适合测试和本地运行，但不提供持久化保证。
- 账号上下文通过 Runtime 的进程内请求桥读取 account 模块，不依赖网关 Host、本机回环地址或 `RUNTIME_ADDR`。

## Environment Variables

- `ADMIN_API_KEY` — 调用 account 模块内部管理接口时附加的 API Key，默认空。
- 内部端点由 runtime 校验令牌后注入 `X-Internal-Authenticated: true`；模块不读取或保存令牌。

## Dependencies

- `account` — 调用 `GET /api/account/me` 和 `GET /api/account/detail` 获取当前后台账号、超管状态和角色范围。

## Dependents

- `permission`
