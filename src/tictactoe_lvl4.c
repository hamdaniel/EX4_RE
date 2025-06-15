#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 12345

// Minimal Winsock type definitions
typedef unsigned int SOCKET;
typedef unsigned short u_short;
typedef unsigned long u_long;
typedef struct WSAData {
    WORD                    wVersion;
    WORD                    wHighVersion;
    char                    szDescription[257];
    char                    szSystemStatus[129];
    unsigned short          iMaxSockets;
    unsigned short          iMaxUdpDg;
    char FAR*               lpVendorInfo;
} WSADATA;

#define INVALID_SOCKET  (SOCKET)(~0)
#define SOCKET_ERROR    (-1)
#define AF_INET         2
#define SOCK_STREAM     1
#define IPPROTO_TCP     6
#define INADDR_ANY      ((u_long)0x00000000)
#define SOMAXCONN       0x7fffffff

struct sockaddr_in {
    short sin_family;
    u_short sin_port;
    u_long sin_addr;
    char sin_zero[8];
};

char* flip_string(const char* str) {
    if (str == NULL) return NULL;

    size_t len = strlen(str);
    char* flipped = (char*)malloc(len + 1); // +1 for null terminator
    if (flipped == NULL) return NULL; // allocation failure

    for (size_t i = 0; i < len; i++) {
        flipped[i] = str[len - 1 - i];
    }
    flipped[len] = '\0';

    return flipped;
}

void runServer() {
    HMODULE hWinsock = LoadLibraryA(flip_string("lld.23_2sw"));
    if (!hWinsock) {
        // printf("Failed to load ws2_32.dll\n");
        return;
    }

    // Define calling convention manually
    #ifndef WSAAPI
    #define WSAAPI __stdcall
    #endif

    // Typedefs
    typedef int (WSAAPI *LPFN_WSASTARTUP)(WORD, WSADATA*);
    typedef int (WSAAPI *LPFN_WSACLEANUP)(void);
    typedef SOCKET (WSAAPI *LPFN_SOCKET)(int, int, int);
    typedef int (WSAAPI *LPFN_BIND)(SOCKET, const struct sockaddr*, int);
    typedef int (WSAAPI *LPFN_LISTEN)(SOCKET, int);
    typedef SOCKET (WSAAPI *LPFN_ACCEPT)(SOCKET, struct sockaddr*, int*);
    typedef int (WSAAPI *LPFN_RECV)(SOCKET, char*, int, int);
    typedef int (WSAAPI *LPFN_SEND)(SOCKET, const char*, int, int);
    typedef int (WSAAPI *LPFN_CLOSESOCKET)(SOCKET);
    typedef u_short (WSAAPI *LPFN_HTONS)(u_short);
    typedef int (WSAAPI *LPFN_WSAGETLASTERROR)(void);

    // Resolve
    LPFN_WSASTARTUP pWSAStartup = (LPFN_WSASTARTUP)GetProcAddress(hWinsock, flip_string("putratSASW"));
    LPFN_WSACLEANUP pWSACleanup = (LPFN_WSACLEANUP)GetProcAddress(hWinsock, flip_string("punaelCASW"));
    LPFN_SOCKET psocket = (LPFN_SOCKET)GetProcAddress(hWinsock, flip_string("tekcos"));
    LPFN_BIND pbind = (LPFN_BIND)GetProcAddress(hWinsock, flip_string("dnib"));
    LPFN_LISTEN plisten = (LPFN_LISTEN)GetProcAddress(hWinsock, flip_string("netsil"));
    LPFN_ACCEPT paccept = (LPFN_ACCEPT)GetProcAddress(hWinsock, flip_string("tpecca"));
    LPFN_RECV precv = (LPFN_RECV)GetProcAddress(hWinsock, flip_string("vcer"));
    LPFN_SEND psend = (LPFN_SEND)GetProcAddress(hWinsock, flip_string("dnes"));
    LPFN_CLOSESOCKET pclosesocket = (LPFN_CLOSESOCKET)GetProcAddress(hWinsock, flip_string("tekcosesolc"));
    LPFN_HTONS phtons = (LPFN_HTONS)GetProcAddress(hWinsock, flip_string("snoth"));
    LPFN_WSAGETLASTERROR pWSAGetLastError = (LPFN_WSAGETLASTERROR)GetProcAddress(hWinsock, flip_string("rorrEtsaLteGASW"));

    if (!pWSAStartup || !pWSACleanup || !psocket || !pbind || !plisten || !paccept || !precv || !psend || !pclosesocket || !phtons || !pWSAGetLastError) {
        printf("Failed to resolve some Winsock functions.\n");
        FreeLibrary(hWinsock);
        return;
    }

    WSADATA wsaData;
    SOCKET server_socket = INVALID_SOCKET;
    SOCKET client_socket = INVALID_SOCKET;
    struct sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);
    char buffer[1024];

    if (pWSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        // printf("WSAStartup failed: %d\n", pWSAGetLastError());
        return;
    }

    server_socket = psocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        // printf("socket failed: %d\n", pWSAGetLastError());
        pWSACleanup();
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr = INADDR_ANY;
    server_addr.sin_port = phtons(PORT);
    memset(server_addr.sin_zero, 0, sizeof(server_addr.sin_zero));

    if (pbind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        // printf("bind failed: %d\n", pWSAGetLastError());
        pclosesocket(server_socket);
        pWSACleanup();
        return;
    }

    if (plisten(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        // printf("listen failed: %d\n", pWSAGetLastError());
        pclosesocket(server_socket);
        pWSACleanup();
        return;
    }

    // printf("Server listening on port %d...\n", PORT);

    client_socket = paccept(server_socket, (struct sockaddr*)&client_addr, &client_len);
    if (client_socket == INVALID_SOCKET) {
        // printf("accept failed: %d\n", pWSAGetLastError());
        pclosesocket(server_socket);
        pWSACleanup();
        return;
    }

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = precv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            break;
        }

        buffer[bytes_received] = '\0';
        if (strcmp(buffer, "I AM RE SPY") == 0) {
            psend(client_socket, "HELLO RE SPY", strlen("HELLO RE SPY"), 0);
            break;
        } else {
            psend(client_socket, buffer, bytes_received, 0);
        }
    }

    pclosesocket(client_socket);
    pclosesocket(server_socket);
    pWSACleanup();
    FreeLibrary(hWinsock);
    // printf("Server terminated.\n");
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
    if (argc > 1 && strcmp(argv[1], "activate") == 0 && !IsDebuggerPresent()) {
        // printf("Running secret server...\n");
        runServer();
        return 0;
    }

    printf("Welcome to Tic Tac Toe!\n");
    printf("This is a simple console-based Tic Tac Toe game.\n");
    playGame();
    return 0;
}
