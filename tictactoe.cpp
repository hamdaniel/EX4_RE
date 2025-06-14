#include <iostream>
#include <vector>
#include <string>

using namespace std;

char board[9] = { '1','2','3','4','5','6','7','8','9' };

void DrawBoard() {
    for (int i = 0; i < 9; i++) {
        cout << " " << board[i] << " ";
        if ((i + 1) % 3 == 0) {
            cout << "\n";
            if (i < 6) cout << "---+---+---\n";
        } else {
            cout << "|";
        }
    }
    cout << "\n";
}

bool IsWin() {
    const int wins[8][3] = {
        {0,1,2}, {3,4,5}, {6,7,8}, // rows
        {0,3,6}, {1,4,7}, {2,5,8}, // cols
        {0,4,8}, {2,4,6}           // diagonals
    };
    for (auto& w : wins) {
        if (board[w[0]] == board[w[1]] && board[w[1]] == board[w[2]])
            return true;
    }
    return false;
}

bool IsDraw() {
    for (int i = 0; i < 9; i++) {
        if (board[i] != 'X' && board[i] != 'O') return false;
    }
    return true;
}

bool MakeMove(int pos, char player) {
    if (pos < 1 || pos > 9) return false;
    if (board[pos - 1] == 'X' || board[pos - 1] == 'O') return false;
    board[pos - 1] = player;
    return true;
}

void playGame()
{
	char currentPlayer = 'X';
    while (true) {
        DrawBoard();
        cout << "Player " << currentPlayer << ", enter position (1-9): ";
        int move;
        cin >> move;
        if (!MakeMove(move, currentPlayer)) {
            cout << "Invalid move. Try again.\n";
            system("pause");
            continue;
        }
        if (IsWin()) {
            DrawBoard();
            cout << "Player " << currentPlayer << " wins!\n";
            break;
        }
        if (IsDraw()) {
            DrawBoard();
            cout << "It's a draw!\n";
            break;
        }
        currentPlayer = (currentPlayer == 'X') ? 'O' : 'X';
    }
}
int main(int argc, char* argv[]) {
	printf("Welcome to Tic Tac Toe!\n");
	printf("This is a simple console-based Tic Tac Toe game.\n");
	playGame();
    return 0;
}
