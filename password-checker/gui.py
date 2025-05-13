import tkinter as tk
from tkinter import ttk, messagebox
from main import password_strength, generate_strong_password
import zxcvbn

class PasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Password Guardian")
        self.root.geometry("800x600")
        self.root.configure(bg='#2D3142')
         
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Color palette
        self.colors = {
            'background': '#2D3142',
            'primary': '#4F5D75',
            'secondary': '#BFC0C0',
            'accent': '#EF8354',
            'text': '#FFFFFF',
            'success': '#4CAF50',
            'warning': '#FFC107',
            'danger': '#F44336'
        }
        
        # Configure styles
        self.style.configure('TFrame', background=self.colors['background'])
        self.style.configure('TLabel', background=self.colors['background'], foreground=self.colors['text'])
        self.style.configure('TButton', background=self.colors['primary'], foreground=self.colors['text'],
                           padding=8, font=('Helvetica', 10, 'bold'))
        self.style.map('TButton',
                      background=[('active', self.colors['accent']), ('pressed', self.colors['accent'])],
                      foreground=[('active', self.colors['text']), ('pressed', self.colors['text'])])
        self.style.configure('TEntry', fieldbackground=self.colors['secondary'], font=('Courier', 14))
        self.style.configure('Horizontal.TProgressbar', thickness=25, troughcolor=self.colors['primary'],
                           background=self.colors['success'], lightcolor=self.colors['success'],
                           darkcolor=self.colors['success'])
        
        self.create_widgets()

    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(padx=30, pady=30, fill=tk.BOTH, expand=True)
        
        # Algorithm selection
        algo_frame = ttk.Frame(main_frame)
        algo_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(algo_frame, text="Algorithm:").pack(side=tk.LEFT)
        self.algorithm_var = tk.StringVar(value="Custom Algorithm")
        algo_combo = ttk.Combobox(algo_frame, textvariable=self.algorithm_var, 
                     values=["Custom Algorithm", "zxcvbn"],
                     state="readonly", width=20)
        algo_combo.pack(side=tk.LEFT)
        algo_combo.bind('<<ComboboxSelected>>', lambda e: self.check_password())
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(header_frame, text="🔒 PASSWORD GUARDIAN", font=('Helvetica', 18, 'bold'),
                 foreground=self.colors['accent']).pack(side=tk.LEFT)
        
        # Input Section
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(input_frame, text="Enter Password:", font=('Helvetica', 12)).pack(side=tk.LEFT, padx=5)
        
        self.password_entry = ttk.Entry(input_frame, width=30, font=('Courier', 14))
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.password_entry.bind('<KeyRelease>', lambda e: self.check_password())
        
        # Visibility toggle
        self.show_password = tk.BooleanVar(value=False)
        ttk.Checkbutton(input_frame, text="👁", style='Toolbutton',
                       variable=self.show_password,
                       command=self.toggle_password).pack(side=tk.LEFT, padx=5)
        
        # Button Panel
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=15)
        
        ttk.Button(btn_frame, text="✨ Generate Strong Password", command=self.generate_password).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="🧹 Clear", command=self.clear).pack(side=tk.LEFT, padx=8)
        
        # Strength Meter
        meter_frame = ttk.Frame(main_frame)
        meter_frame.pack(fill=tk.X, pady=15)
        
        ttk.Label(meter_frame, text="Security Level:", font=('Helvetica', 12)).pack(side=tk.LEFT)
        self.meter = ttk.Progressbar(meter_frame, orient=tk.HORIZONTAL, length=400)
        self.meter.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        # Metrics Display
        metrics_frame = ttk.Frame(main_frame)
        metrics_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left Column - Strength Info
        left_col = ttk.Frame(metrics_frame)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, padx=10, expand=True)
        
        ttk.Label(left_col, text="Security Assessment", font=('Helvetica', 14, 'bold'),
                foreground=self.colors['accent']).pack(anchor=tk.W, pady=5)
        
        self.strength_label = ttk.Label(left_col, text="Strength: ", font=('Helvetica', 12))
        self.strength_label.pack(anchor=tk.W)
        
        self.score_label = ttk.Label(left_col, text="Score: ", font=('Helvetica', 12))
        self.score_label.pack(anchor=tk.W)
        
        self.nist_label = ttk.Label(left_col, text="NIST Compliance Issues: ", font=('Helvetica', 12))
        self.nist_label.pack(anchor=tk.W)
        
        self.entropy_label = ttk.Label(left_col, text="Shannon Entropy: ", font=('Helvetica', 12))
        self.entropy_label.pack(anchor=tk.W)
        
        self.pwned_label = ttk.Label(left_col, text="Pwned Check: ", font=('Helvetica', 12))
        self.pwned_label.pack(anchor=tk.W)
        
        # Right Column - Findings
        right_col = ttk.Frame(metrics_frame)
        right_col.pack(side=tk.LEFT, fill=tk.BOTH, padx=10, expand=True)
        
        ttk.Label(right_col, text="Security Findings", font=('Helvetica', 14, 'bold'),
                foreground=self.colors['accent']).pack(anchor=tk.W, pady=5)
        
        self.findings_text = tk.Text(right_col, height=8, width=40, wrap=tk.WORD,
                                   bg=self.colors['primary'], fg=self.colors['text'],
                                   font=('Helvetica', 10), relief=tk.FLAT, padx=10, pady=10)
        self.findings_text.pack(fill=tk.BOTH, expand=True)
        
    def toggle_password(self):
        show = self.show_password.get()
        self.password_entry.config(show='' if show else '•')
        
    def update_meter_style(self, strength):
        color_map = {
            'Banned': self.colors['danger'],
            'Very Weak': self.colors['danger'],
            'Weak': self.colors['warning'],
            'Moderate': '#FF9800',
            'Strong': self.colors['success'],
            'Very Strong': '#4CAF50',
            'Unbreakable': '#009688'
        }
        self.style.configure('Horizontal.TProgressbar',
                           background=color_map.get(strength, self.colors['primary']),
                           troughcolor=self.colors['primary'])

    def check_password(self):
        password = self.password_entry.get()
        if not password.strip():
            self.clear()
            return
            
        # Use selected algorithm
        if self.algorithm_var.get() == "zxcvbn":
            result = self.analyze_with_zxcvbn(password)
        else:
            result = password_strength(password)
        
        # Update metrics
        self.strength_label.config(text=f"Strength: {result['strength']}")
        self.score_label.config(text=f"Score: {result['score']:.1f}/150")
        self.nist_label.config(text=f"NIST Compliance Issues: {len(result.get('nist', []))}")
        self.entropy_label.config(text=f"Shannon Entropy: {result.get('entropy', 0):.1f} bits")
        self.pwned_label.config(text=f"Pwned Check: {'Compromised' if result.get('pwned', False) else 'Safe'}")
        
        # Update progress bar
        self.meter['value'] = min(result['score'], 150)
        self.update_meter_style(result['strength'])
        
        # Update findings
        self.findings_text.config(state=tk.NORMAL)
        self.findings_text.delete(1.0, tk.END)
        
        if result.get('issues'):
            self.findings_text.insert(tk.END, "🚨 Critical Issues:\n", 'danger')
            for issue in result.get('issues', []):
                self.findings_text.insert(tk.END, f"• {issue}\n", 'danger')
                
        if result.get('warnings'):
            self.findings_text.insert(tk.END, "\n⚠️ Warnings:\n", 'warning')
            for warning in result.get('warnings', []):
                self.findings_text.insert(tk.END, f"• {warning}\n", 'warning')
        
        # Configure tags
        self.findings_text.tag_config('danger', foreground=self.colors['danger'])
        self.findings_text.tag_config('warning', foreground=self.colors['warning'])
        self.findings_text.config(state=tk.DISABLED)

    def analyze_with_zxcvbn(self, password):
        result = zxcvbn.zxcvbn(password)
        feedback = {
            'strength': self.map_zxcvbn_score(result['score']),
            'score': result['score'] * 30,  # Scale to 0-150
            'issues': [],
            'warnings': []
        }
        
        if result['score'] <= 2:
            feedback['issues'].append(f"Crack time: {result['crack_times_display']['offline_slow_hashing_1e4_per_second']}")
        else:
            feedback['warnings'].append(f"Crack time: {result['crack_times_display']['offline_slow_hashing_1e4_per_second']}")
        
        if result['feedback']['warning']:
            feedback['warnings'].append(result['feedback']['warning'])
        feedback['warnings'].extend(result['feedback']['suggestions'])
        
        return feedback

    def map_zxcvbn_score(self, score):
        mapping = {
            0: "Banned", 1: "Very Weak", 
            2: "Weak", 3: "Moderate", 
            4: "Strong"
        }
        return mapping.get(score, "Unknown")

    def generate_password(self):
        generated = generate_strong_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, generated)
        self.check_password()
        self.show_password.set(False)
        self.toggle_password()

    def clear(self):
        self.password_entry.delete(0, tk.END)
        self.strength_label.config(text="Strength: ")
        self.score_label.config(text="Score: ")
        self.nist_label.config(text="NIST Compliance Issues: ")
        self.entropy_label.config(text="Shannon Entropy: ")
        self.pwned_label.config(text="Pwned Check: ")
        self.meter['value'] = 0
        self.findings_text.config(state=tk.NORMAL)
        self.findings_text.delete(1.0, tk.END)
        self.findings_text.config(state=tk.DISABLED)
        self.update_meter_style('')
        self.show_password.set(False)
        self.toggle_password()

if __name__ == "__main__":
    root = tk.Tk()
    root.tk.call('tk', 'scaling', 2.0)  # HiDPI scaling
    app = PasswordApp(root)
    root.mainloop()