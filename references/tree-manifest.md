# 严格目录清单校验器

`scripts/tree_manifest.py` 使用 Python 标准库，建议 Python 3.10 或更高版本。它不会操作聊天、Git 状态、容器、网络，也不会复制、改名或删除源目录。

## 命令与输出

所有路径使用绝对路径。清单和报告的父目录必须已存在，并在被扫描目录之外；调用者负责该私有目录的 Windows ACL。工具不改权限、不覆盖任何已有输出。

```powershell
$pythonExe = '<verified-python-absolute-path>'
$manifestTool = '<skill-dir>/scripts/tree_manifest.py'
& $pythonExe -X utf8 $manifestTool capture --root '<old-root>' --manifest '<private-dir>/before.json'
if ($LASTEXITCODE -ne 0) { throw '清单采集未完成' }

# 在已授权的外部流程改名后验证；本工具不做改名。
& $pythonExe -X utf8 $manifestTool verify --root '<archive-root>' --manifest '<private-dir>/before.json' --report '<private-dir>/after.json'
if ($LASTEXITCODE -ne 0) { throw '归档内容尚未核验通过' }
```

| 退出码 | 含义 |
| --- | --- |
| 0 | 清单采集成功，或验证内容相等；以 stdout 的 `captured`／`matched` 区分 |
| 1 | 验证发现差异，私有报告列出新增、缺失、内容变化文件及目录变化 |
| 2 | 输入、读取、稳定性或输出条件不满足，操作停止；不能当作无差异 |

stdout 只输出固定状态、计数和错误类别；stderr 定期输出哈希进度，不含文件名或内容。清单与报告含完整路径，属于私有证据，不应提交到公共或代码仓库。

## 覆盖范围

- 所有普通文件的相对路径、大小和 SHA-256，包括隐藏文件及 `.git` 下文件。
- 所有子目录，包括空目录；大小写差异也作为目录／文件清单差异保留。
- 读取前后文件身份、大小与时间信息，以及结束时的树结构／元数据复核。
- 根目录、祖先路径和树中的符号链接／junction／reparse point 一律拒绝，不跟随它们，也没有忽略参数。遇到这种布局应先盘点其作用，再选择支持该布局的独立验证方法。
- UTF-8 清单、严格 schema、重复路径及路径穿越项拒绝、已有证据不可覆盖。

单个文件分块读取；清单保留在内存中，因此特别大的目录树要先评估内存。写输出使用独占创建并刷新，进程被中断可能留下不完整 JSON；下一次读取会拒绝，重试使用新的输出名，不能将半份证据当作成功。

## 正确解释结果

这不是文件系统原子快照。扫描期间和扫描到改名之间必须有可确认的写入静止条件；工具检查用于发现常见变化，不能证明不存在任意并发或恶意修改。

`matched` 证明所列目录结构与普通文件内容一致，不验证 ACL、所有者、NTFS 备用数据流、硬链接拓扑、扩展属性、运行服务或聊天配置。仅修改时间等元数据不会被误报为内容变化。若任务需要这些性质，另做对应清单和恢复验证。

完成清单也不是备份；它不能恢复原始内容。改名前应已具备相应备份或可恢复归档，且清单本身应保存在可验证的私有位置。

## 自测

```powershell
python -X utf8 '<skill-dir>/scripts/test_tree_manifest.py'
```

自测只创建合成临时目录，覆盖中文／空格、完整改名后验证、同大小内容变更、隐藏 Git 引用、空目录、读取中变化、已有输出保护、错误退出码和脱敏输出。Windows 上额外创建临时 junction 证明拒绝行为；账号无符号链接能力时对应 symlink 子项会明确跳过，不把它报告为通过。
