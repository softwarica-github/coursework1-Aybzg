import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import socket
import threading
import ipaddress

# Function to validate an IP address
def valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False
    
# Function to scan a single port
def scan_port(host, port, output, sem, results, status_var, scan_btn):
    with sem:  # Use semaphore to limit concurrency
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as scanner:
                scanner.settimeout(1)
                result = scanner.connect_ex((host, port))
                if result == 0:
                    msg = f"Port {port}: Open\n"
                else:
                    msg = f"Port {port}: Closed\n"
                output.insert(tk.END, msg)
                results.append(msg)
        except Exception as e:
            msg = f"Error scanning port {port}: {e}\n"
            output.insert(tk.END, msg)
        finally:
            status_var.set(f"Completed scanning port {port}")
            if port == int(ports_entry.get().split('-')[1]):  # Check if it's the last port
                scan_btn.config(state=tk.NORMAL)
                status_var.set("Scan completed.")
# Main GUI application
def gui():
    app = tk.Tk()
    app.title("Cool Port Scanner")
    app.geometry("800x600")  # Set initial size of the window
    app.configure(bg='#333333')

    # Custom style
    style = ttk.Style(app)
    style.theme_use("clam")
    style.configure("TLabel", background="#333333", foreground="#FFFFFF")
    style.configure("TButton", background="#333333", foreground="#FFFFFF", borderwidth=1)
    style.configure("TFrame", background="#333333", relief="flat")
    style.map("TButton", background=[('active', '#0052cc'), ('disabled', '#333333')])
    # Menu Bar
    menu_bar = Menu(app, bg="#333333", fg="#FFFFFF", relief=tk.FLAT)
    app.config(menu=menu_bar)

    # File Menu
    file_menu = Menu(menu_bar, tearoff=0, bg="#333333", fg="#FFFFFF")
    menu_bar.add_cascade(label="File", menu=file_menu)

    # Status Bar
    status_var = tk.StringVar()
    status_var.set("Ready")
    status_bar = ttk.Label(app, textvariable=status_var, background="#555555", foreground="#FFFFFF", relief=tk.SUNKEN, anchor=tk.W)
    status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    # Function to save results
    def save_results():
        text = output_text.get("1.0", tk.END)
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file:
            with open(file, "w") as file_output:
                file_output.write(text)
            status_var.set("Results saved successfully.")
    # Function to clear the output
    def clear_output():
        output_text.delete("1.0", tk.END)
        status_var.set("Output cleared.")

    # Function to exit the application
    def exit_app():
        app.quit()

    file_menu.add_command(label="Save Results", command=save_results)
    file_menu.add_command(label="Clear Output", command=clear_output)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=exit_app)

    # Input frame for host, ports, and controls
    input_frame = ttk.Frame(app, padding="10")
    input_frame.pack(padx=10, pady=5, fill='x', expand=True)

    global host_entry, ports_entry
    # Host Entry
    ttk.Label(input_frame, text="Host IP:").grid(column=0, row=0, sticky=tk.W, pady=2)
    host_entry = ttk.Entry(input_frame, width=30)
    host_entry.grid(column=1, row=0, sticky=tk.EW, pady=2, padx=5)

    # Ports Entry
    ttk.Label(input_frame, text="Ports Range:").grid(column=0, row=1, sticky=tk.W, pady=2)
    ports_entry = ttk.Entry(input_frame, width=30)
    ports_entry.grid(column=1, row=1, sticky=tk.EW, pady=2, padx=5)

    # Max Threads Entry
    ttk.Label(input_frame, text="Max Threads:").grid(column=2, row=0, padx=5, sticky=tk.W)
    concurrency_entry = ttk.Entry(input_frame, width=10)
    concurrency_entry.insert(0, "50")
    concurrency_entry.grid(column=3, row=0, sticky=tk.EW, padx=5)
    # Output frame for scan results and actions
    output_frame = ttk.Frame(app, padding="10")
    output_frame.pack(padx=10, pady=5, fill='both', expand=True)
    output_text = scrolledtext.ScrolledText(output_frame, width=70, height=25)
    output_text.pack(pady=10, fill='both', expand=True)
    # Scan function with IP validation and threading enhancements
    def on_scan():
        host = host_entry.get()
        if not valid_ip(host):
            messagebox.showerror("Invalid Input", "Please enter a valid IP address.")
            return

        ports = ports_entry.get().split('-')
        max_threads = int(concurrency_entry.get())
        if len(ports) != 2 or not max_threads:
            messagebox.showerror("Invalid Input", "Please enter a valid port range and max threads.")
            return
        start_port, end_port = int(ports[0]), int(ports[1])
        sem = threading.Semaphore(max_threads)
        results = []

        scan_btn.config(state=tk.DISABLED)  # Disable the scan button during scan
        status_var.set("Scanning...")

        for port in range(start_port, end_port + 1):
            threading.Thread(target=scan_port, args=(host, port, output_text, sem, results, status_var, scan_btn), daemon=True).start()
    # Scan Button
    scan_btn = ttk.Button(input_frame, text="Scan", command=on_scan)
    scan_btn.grid(column=3, row=1, pady=5, sticky=tk.E)
    app.mainloop()

if __name__ == "__main__":
    gui()
