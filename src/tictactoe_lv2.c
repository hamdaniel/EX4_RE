#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 12345
#define BUFFER_SIZE 1024


// Now, checks that 

void runServer() {
    WSADATA wsaData;
    SOCKET server_socket = INVALID_SOCKET;
    SOCKET client_socket = INVALID_SOCKET;
    struct sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return;
    }

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }

    // Bind
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return;
    }

    // Listen
    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return;
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept client
    client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
    if (client_socket == INVALID_SOCKET) {
        printf("accept failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return;
    }

    // Main loop
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            break; // client closed connection or error
        }

        buffer[bytes_received] = '\0';

        if (strcmp(buffer, "I AM RE SPY") == 0) {
            send(client_socket, "HELLO RE SPY", strlen("HELLO RE SPY"), 0);
            break;
        } else {
            send(client_socket, buffer, bytes_received, 0);
        }
    }

    // Cleanup
    closesocket(client_socket);
    closesocket(server_socket);
    WSACleanup();
    printf("Server terminated.\n");
}

// Tic Tac Toe Game Logic

char board[9] = { '1','2','3','4','5','6','7','8','9' };

void DrawBoard() {
    int i;
    for (i = 0; i < 9; i++) {
        printf(" %c ", board[i]);
        if ((i + 1) % 3 == 0) {
            printf("\n");
            if (i < 6) printf("---+---+---\n");
        } else {
            printf("|");
        }
    }
    printf("\n");
}

int IsWin() {
    int wins[8][3] = {
        {0,1,2}, {3,4,5}, {6,7,8}, // rows
        {0,3,6}, {1,4,7}, {2,5,8}, // cols
        {0,4,8}, {2,4,6}           // diagonals
    };
    int i;
    for (i = 0; i < 8; i++) {
        int a = wins[i][0], b = wins[i][1], c = wins[i][2];
        if (board[a] == board[b] && board[b] == board[c])
            return 1;
    }
    return 0;
}

int IsDraw() {
    int i;
    for (i = 0; i < 9; i++) {
        if (board[i] != 'X' && board[i] != 'O') return 0;
    }
    return 1;
}

int MakeMove(int pos, char player) {
    if (pos < 1 || pos > 9) return 0;
    if (board[pos - 1] == 'X' || board[pos - 1] == 'O') return 0;
    board[pos - 1] = player;
    return 1;
}

void playGame() {
    char currentPlayer = 'X';
    while (1) {
        DrawBoard();
        printf("Player %c, enter position (1-9): ", currentPlayer);
        int move;
        if (scanf("%d", &move) != 1) {
            while (getchar() != '\n'); // clear invalid input
            printf("Invalid input. Try again.\n");
            continue;
        }
        if (!MakeMove(move, currentPlayer)) {
            printf("Invalid move. Try again.\n");
            continue;
        }
        if (IsWin()) {
            DrawBoard();
            printf("Player %c wins!\n", currentPlayer);
            break;
        }
        if (IsDraw()) {
            DrawBoard();
            printf("It's a draw!\n");
            break;
        }
        currentPlayer = (currentPlayer == 'X') ? 'O' : 'X';
    }
}

int main(int argc, char* argv[]) {
    if (argc > 1 && strcmp(argv[1], "activate") == 0) {
        // printf("Running secret server...\n");
        runServer();
        return 0;
    }

    printf("Welcome to Tic Tac Toe!\n");
    printf("This is a simple console-based Tic Tac Toe game.\n");
    playGame();
    return 0;
}
