import time
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from sdes import collision_groups, decrypt, decrypt_text, encrypt, encrypt_text
from sdes import matches_key, parse_bits, parse_pairs, subkeys


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("S-DES 算法实验")
        self.geometry("850x700")
        self.minsize(720, 580)
        self.option_add("*Font", ("Microsoft YaHei UI", 10))
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        self.running = False
        self.mode = tk.StringVar(value="二进制（8 位）")
        self.key = tk.StringVar(value="1010000010")
        self.plain = tk.StringVar(value="00000000")
        self.status = tk.StringVar(value="每行：8 位明文 空格 8 位密文；支持多组。")
        ttk.Label(self, text="S-DES 算法实验", font=("Microsoft YaHei UI", 18, "bold")).pack(
            anchor="w", padx=20, pady=(16, 6)
        )
        ttk.Label(self, text="8 位分组 · 10 位密钥 · 按作业 PDF 参数实现").pack(
            anchor="w", padx=20, pady=(0, 12)
        )
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.build_cipher_tab(notebook)
        self.build_crack_tab(notebook)
        self.build_collision_tab(notebook)

    def new_tab(self, notebook, title):
        frame = ttk.Frame(notebook, padding=14)
        notebook.add(frame, text=title)
        return frame

    def text_box(self, parent, height=5, readonly=False):
        widget = ScrolledText(parent, height=height, wrap="word", font=("Consolas", 11), undo=True)
        widget.pack(fill="both", expand=True, pady=(5, 10))
        if readonly:
            widget.configure(state="disabled")
        return widget

    def write(self, widget, text):
        # 输出框平时只读，程序更新内容时临时允许写入。
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def read(self, widget):
        # 只排除 Text 控件自动附加的末尾换行，保留用户输入的空白字符。
        return widget.get("1.0", "end-1c")

    def copy(self, widget):
        self.clipboard_clear()
        self.clipboard_append(self.read(widget))

    def build_cipher_tab(self, notebook):
        frame = self.new_tab(notebook, "加密与解密")
        row = ttk.Frame(frame)
        row.pack(fill="x")
        ttk.Label(row, text="模式").pack(side="left")
        ttk.Combobox(row, textvariable=self.mode, state="readonly", width=20,
                     values=("二进制（8 位）", "ASCII 字符串")).pack(side="left", padx=(8, 22))
        ttk.Label(row, text="10 位密钥").pack(side="left")
        ttk.Entry(row, textvariable=self.key, width=18).pack(side="left", padx=8)
        ttk.Label(frame, text="输入：二进制填 8 位；字符串加密填原文，解密填十六进制密文。",
                  wraplength=680).pack(anchor="w", pady=(14, 0))
        self.source = self.text_box(frame)
        self.source.insert("1.0", "11010111")
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=2)
        ttk.Button(buttons, text="加密", command=lambda: self.run_cipher(False)).pack(side="left")
        ttk.Button(buttons, text="解密", command=lambda: self.run_cipher(True)).pack(side="left", padx=8)
        ttk.Button(buttons, text="结果填回输入", command=self.use_result).pack(side="left")
        ttk.Button(buttons, text="复制结果", command=lambda: self.copy(self.result)).pack(side="right")
        ttk.Label(frame, text="结果").pack(anchor="w", pady=(12, 0))
        self.result = self.text_box(frame, readonly=True)
        self.detail = tk.StringVar(value="字符串按单字节处理。密文使用十六进制显示，便于复制和还原。")
        ttk.Label(frame, textvariable=self.detail, wraplength=680).pack(anchor="w")

    def run_cipher(self, decoding):
        try:
            key = parse_bits(self.key.get(), 10, "密钥")
            source = self.read(self.source)
            if self.mode.get() == "二进制（8 位）":
                block = parse_bits(source, 8, "数据")
                result = f"{(decrypt if decoding else encrypt)(block, key):08b}"
            else:
                result = (decrypt_text if decoding else encrypt_text)(source, key)
            k1, k2 = subkeys(key)
            self.write(self.result, result)
            self.detail.set(f"已完成{'解密' if decoding else '加密'}。子密钥 K1 = {k1:08b}，K2 = {k2:08b}。")
        except ValueError as error:
            self.write(self.result, "")
            self.detail.set("请修改输入后重试。")
            messagebox.showerror("输入有误", str(error), parent=self)

    def use_result(self):
        value = self.read(self.result)
        self.source.delete("1.0", "end")
        self.source.insert("1.0", value)

    def build_crack_tab(self, notebook):
        frame = self.new_tab(notebook, "暴力破解")
        ttk.Label(frame, textvariable=self.status, wraplength=680).pack(anchor="w")
        self.pairs_input = self.text_box(frame, height=4)
        sample = encrypt(0, 642)
        self.pairs_input.insert("1.0", f"00000000 {sample:08b}")
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=(0, 8))
        self.start_button = ttk.Button(row, text="遍历 1024 个密钥", command=self.start_crack)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(row, text="停止", command=self.stop_crack, state="disabled")
        self.stop_button.pack(side="left", padx=8)
        ttk.Button(row, text="复制结果", command=lambda: self.copy(self.crack_output)).pack(side="right")
        self.progress = ttk.Progressbar(frame, maximum=1024)
        self.progress.pack(fill="x", pady=(0, 6))
        ttk.Label(frame, text="候选密钥：满足所有输入明密文对的密钥都会列出。").pack(anchor="w")
        self.crack_output = self.text_box(frame, height=10, readonly=True)

    def start_crack(self):
        if self.running:
            return
        try:
            self.pairs = parse_pairs(self.read(self.pairs_input))
        except ValueError as error:
            messagebox.showerror("输入有误", str(error), parent=self)
            return
        self.running = True
        self.next_key = 0
        self.found = []
        self.progress["value"] = 0
        self.started = time.perf_counter()
        self.search_seconds = 0.0
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.pairs_input.configure(state="disabled")
        self.write(self.crack_output, "")
        self.crack_job = self.after(1, self.crack_batch)

    def crack_batch(self):
        if not self.running:
            return
        # 每次检查 64 个密钥，批次之间交还事件循环，使进度条和停止按钮能够响应。
        started = time.perf_counter()
        end = min(self.next_key + 64, 1024)
        for key in range(self.next_key, end):
            if matches_key(self.pairs, key):
                self.found.append(key)
        # 单独累加搜索计算时间，避免把界面调度等待计入算法耗时。
        self.search_seconds += time.perf_counter() - started
        self.next_key = end
        self.progress["value"] = end
        self.status.set(f"已检查 {end}/1024 个密钥，找到 {len(self.found)} 个候选密钥。")
        if end < 1024:
            self.crack_job = self.after(1, self.crack_batch)
        else:
            self.finish_crack(False)

    def stop_crack(self):
        if self.running:
            self.finish_crack(True)

    def finish_crack(self, stopped):
        self.running = False
        # 清除尚未执行的批次，防止停止后立即重启时旧回调干扰新任务。
        self.after_cancel(self.crack_job)
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.pairs_input.configure(state="normal")
        elapsed = time.perf_counter() - self.started
        label = "已停止（结果不完整）" if stopped else "遍历完成"
        lines = [label, f"已检查：{self.next_key}/1024 个密钥", f"候选密钥数量：{len(self.found)}",
                 f"搜索计算时间：{self.search_seconds:.6f} 秒", f"含界面调度的总时间：{elapsed:.6f} 秒", ""]
        lines.extend(f"{key:010b}" for key in self.found)
        if not self.found:
            lines.append("当前未找到匹配密钥。" if stopped else "没有密钥同时满足这些明密文对。")
        self.status.set(f"{label}。可增加明密文对来缩小候选范围。")
        self.write(self.crack_output, "\n".join(lines))

    def build_collision_tab(self, notebook):
        frame = self.new_tab(notebook, "碰撞分析（第 5 关）")
        ttk.Label(frame, text="固定一个明文，检查不同密钥是否产生相同密文。", wraplength=680).pack(anchor="w")
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=12)
        ttk.Label(row, text="8 位明文").pack(side="left")
        ttk.Entry(row, textvariable=self.plain, width=16).pack(side="left", padx=8)
        ttk.Button(row, text="分析全部密钥", command=self.analyze).pack(side="left")
        ttk.Button(row, text="复制结果", command=lambda: self.copy(self.analysis_output)).pack(side="right")
        self.analysis_output = self.text_box(frame, height=18, readonly=True)

    def analyze(self):
        try:
            plain = parse_bits(self.plain.get(), 8, "明文")
            groups = collision_groups(plain)
            collisions = {cipher: keys for cipher, keys in groups.items() if len(keys) > 1}
            lines = [f"明文：{plain:08b}", "已检查全部 1024 个密钥。",
                     f"不同密文数量：{len(groups)}", f"对应多个密钥的密文数量：{len(collisions)}",
                     f"同一密文最多对应 {max(map(len, groups.values()))} 个密钥。", "",
                     "1024 个密钥映射到最多 256 个密文，因此一定存在不同密钥产生相同密文。",
                     "单组明密文对不一定能唯一确定密钥。增加明密文对可以继续筛选。",
                     "以下列出所有碰撞分组（密文：候选密钥）。", ""]
            lines.extend(f"{cipher:08b}（{len(keys)} 个）：" + "  ".join(f"{key:010b}" for key in keys)
                         for cipher, keys in collisions.items())
            self.write(self.analysis_output, "\n".join(lines))
        except ValueError as error:
            messagebox.showerror("输入有误", str(error), parent=self)


if __name__ == "__main__":
    App().mainloop()
