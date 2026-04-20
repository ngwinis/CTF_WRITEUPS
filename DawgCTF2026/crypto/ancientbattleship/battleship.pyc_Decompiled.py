# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'battleship.py'
# Bytecode version: 3.9.0beta5 (3425)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import tkinter as tk
from tkinter import messagebox
import random
import sys
GRID_SIZE = 5
SHIPS = {'Carrier': 2, 'Submarine': 2, 'Destroyer': 2, 'Patrol Boat': 2}
AERO_BLUE = '#d0e8f2'
AERO_GLASS = '#0078d7'
WATER_COLOR = '#e1f5fe'
SHIP_COLOR = '#4caf50'
HIT_COLOR = '#e81123'
MISS_COLOR = '#9e9e9e'
class BattleshipGame:
    def __init__(self, root):
        self.root = root
        self.root.title('You Captured my Battleship!')
        self.root.configure(bg=AERO_BLUE)
        self.move_script = [(2, 4), (2, 3), (2, 1), (0, 0), (1, 1), (3, 1), (3, 4), (2, 2), (0, 4), (3, 3)]
        self.script_index = 0
        self.player_board = [[0] * GRID_SIZE for _ in range(GRID_SIZE)]
        self.ai_board = [[0] * GRID_SIZE for _ in range(GRID_SIZE)]
        self.current_turn = 'Player'
        self.player_health = sum(SHIPS.values())
        self.ai_health = sum(SHIPS.values())
        self.game_over = False
        self.setup_ui()
        self.place_ships(self.player_board)
        self.place_ships(self.ai_board)
        self.update_player_grid()
    def setup_ui(self):
        self.info_frame = tk.Frame(self.root, bg=AERO_BLUE)
        self.info_frame.pack(pady=10)
        self.turn_label = tk.Label(self.info_frame, text='Your Turn', font=('Segoe UI', 14, 'bold'), bg=AERO_BLUE, fg=AERO_GLASS)
        self.turn_label.pack()
        self.player_score_label = tk.Label(self.info_frame, text=f'Your Health: {self.player_health}', font=('Segoe UI', 10), bg=AERO_BLUE)
        self.player_score_label.pack(side=tk.LEFT, padx=20)
        self.ai_score_label = tk.Label(self.info_frame, text=f'AI Health: {self.ai_health}', font=('Segoe UI', 10), bg=AERO_BLUE)
        self.ai_score_label.pack(side=tk.RIGHT, padx=20)
        self.grid_frame = tk.Frame(self.root, bg=AERO_BLUE)
        self.grid_frame.pack(padx=20, pady=10)
        tk.Label(self.grid_frame, text='PLAYER SECTOR', font=('Segoe UI', 8, 'bold'), bg=AERO_BLUE, fg='#555555').grid(row=0, column=0)
        tk.Label(self.grid_frame, text='ENEMY SECTOR', font=('Segoe UI', 8, 'bold'), bg=AERO_BLUE, fg='#555555').grid(row=0, column=1)
        self.p_canvas = tk.Frame(self.grid_frame, bg=AERO_BLUE)
        self.p_canvas.grid(row=1, column=0, padx=10)
        self.a_canvas = tk.Frame(self.grid_frame, bg=AERO_BLUE)
        self.a_canvas.grid(row=1, column=1, padx=10)
        self.player_buttons = []
        self.ai_buttons = []
        for r in range(GRID_SIZE):
            p_row, a_row = ([], [])
            for c in range(GRID_SIZE):
                pb = tk.Button(self.p_canvas, text='', width=4, height=2, bg=WATER_COLOR, relief='flat', highlightthickness=1, state='disabled')
                pb.grid(row=r, column=c, padx=1, pady=1)
                p_row.append(pb)
                ab = tk.Button(self.a_canvas, text='', width=4, height=2, bg=WATER_COLOR, relief='flat', highlightthickness=1, command=lambda row, col=r, c=c: self.player_click(row, col))
                ab.grid(row=r, column=c, padx=1, pady=1)
                a_row.append(ab)
            self.player_buttons.append(p_row)
            self.ai_buttons.append(a_row)
    def player_click(self, r, c):
        if self.current_turn!= 'Player' or self.game_over:
            return None
        else:
            btn = self.ai_buttons[r][c]
            if btn.cget('state') == tk.DISABLED:
                return None
            else:
                if self.ai_board[r][c] == 1:
                    self.ai_board[r][c] = 2
                    self.ai_health -= 1
                    btn.config(bg=HIT_COLOR, state=tk.DISABLED)
                    self.ai_score_label.config(text=f'AI Health: {self.ai_health}')
                    if self.ai_health == 0:
                        self.end_game('VICTORY')
                else:
                    self.ai_board[r][c] = 3
                    btn.config(bg=MISS_COLOR, state=tk.DISABLED)
                    self.ai_turn_with_delay()
    def ai_turn_with_delay(self):
        self.current_turn = 'AI'
        self.turn_label.config(text='AI Thinking...', fg='#555555')
        self.root.after(800, self.ai_turn)
    def ai_turn(self):
        if self.game_over:
            return None
        else:
            if self.script_index < len(self.move_script):
                r, c = self.move_script[self.script_index]
                self.script_index += 1
            else:
                messagebox.showinfo('Tactical Update', 'The AI is out of moves. You win!')
                sys.exit(0)
            hit = self.player_board[r][c] == 1
            if hit:
                self.player_board[r][c] = 2
                self.player_health -= 1
                self.player_buttons[r][c].config(bg=HIT_COLOR)
                self.player_score_label.config(text=f'Your Health: {self.player_health}')
                if self.player_health == 0:
                    self.end_game('DEFEAT')
                    return None
                else:
                    self.root.after(800, self.ai_turn)
            else:
                self.player_board[r][c] = 3
                self.player_buttons[r][c].config(bg=MISS_COLOR)
                self.current_turn = 'Player'
                self.turn_label.config(text='Your Turn', fg=AERO_GLASS)
    def place_ships(self, board):
        for ship_name, length in SHIPS.items():
            placed = False
            while not placed:
                r, c = (random.randint(0, GRID_SIZE - 1), random.randint(0, GRID_SIZE - 1))
                direction = random.choice(['H', 'V'])
                if self.can_place(board, r, c, length, direction):
                    for i in range(length):
                        if direction == 'H':
                            board[r][c + i] = 1
                        else:
                            board[r + i][c] = 1
                    placed = True
    def can_place(self, board, r, c, length, direction):
        if direction == 'H':
            if c + length > GRID_SIZE:
                return False
            else:
                return all((board[r][c + i] == 0 for i in range(length)))
        else:
            if r + length > GRID_SIZE:
                return False
            else:
                return all((board[r + i][c] == 0 for i in range(length)))
    def update_player_grid(self):
        for r in range(GRID_SIZE):
            for c in range(GRID_SIZE):
                if self.player_board[r][c] == 1:
                    self.player_buttons[r][c].config(bg=SHIP_COLOR)
    def end_game(self, result):
        self.game_over = True
        self.turn_label.config(text=f'GAME OVER: {result}')
        messagebox.showinfo('Result', f'Game Finished: {result}')
if __name__ == '__main__':
    root = tk.Tk()
    root.option_add('*Font', 'SegoeUI 9')
    game = BattleshipGame(root)
    root.mainloop()