// SPDX-License-Identifier: MIT
// Define la versión del compilador de Solidity a utilizar.
// En este caso, es compatible con versiones desde 0.8.2 hasta antes de 0.9.0.

pragma solidity ^0.8.13;

contract SupplyChain {

    error NoApproved(); // Se emite cuando una dirección no autorizada intenta ejecutar una función protegida.
    error EntradaInvalida(string campo); // Para entradas de datos no válidas, como un nombre.
    /**
    * @notice Acción no autorizada por el rol actual.
    */
    error NoAutorizado(); // Se emite cuando una dirección no autorizada intenta ejecutar una función protegida.


    /**
    * @notice Enum para estados de usuario: pendiente, aprobado, rechazado o cancelado.
    */
    enum UserStatus { 
        Pending,    //Valor 0 
        Approved,   //Valor 1
        Rejected,   //Valor 2
        Canceled    //Valor 3
    }

    /**
    * @notice Enum para los roles básicos de la cadena de suministro.
    */
    enum UserRole { 
        Producer,   //Valor 0
        Factory,    //Valor 1
        Retailer,   //Valor 2
        Consumer    //Valor 3
    }

    /**
    * @notice Enum para el estado de una transferencia de tokens.
    */
    enum TransferStatus {
        Pending,    //Valor 0
        Accepted,   //Valor 1
        Rejected,   //Valor 2
        Cancelled   //Valor 3
    }

    /**
    * @notice Enum para diferenciar tokens de materia prima y producto terminado.
    */ 
    enum TokenType {
        RowMaterial,       //Valor 0
        FinishedProduct    //Valor 1
    }

    struct Token {
        uint256 id;        // Token ID
        address creator;   // Dirección del creador del token
        string name;       // Nombre del token
        uint256 totalSupply; // Suministro o cantidad total del token
        string features;   // Características del token (JSON string)
        uint256 parentId;  // ID del token padre (si es un token hijo)
        uint256 dateCreated;    // Fecha de creación del token
        mapping(address => uint256) balance;    // Mapeo de balances por dirección
    }

    struct Transfer {
        uint256 id;       // ID de la transferencia
        address from;     // Dirección del remitente
        address to;       // Dirección del destinatario
        uint256 tokenId;  // ID del token a transferir
        uint256 dateCreated; // Fecha de creación de la transferencia
        uint256 amount;   // Cantidad de tokens transferidos
        TransferStatus status;
    }

    struct User {
        uint256 id;
        address userAddress;
        string role;
        UserStatus status;
    }

    address public admin;   // Dirección del administrador del contrato
    
    // Contadores para los ids de los tokens, transfers y users
    uint256 public nextTokenId = 1;     // ID del próximo token
    uint256 public nextTransferId = 1;   // ID de la próxima transferencia
    uint256 public nextUserId = 1;       // ID del próximo usuario
    
    // mapping para los tokens, transfers y users
    mapping(uint256 => Token) public tokens;             // Mapeo de tokens por ID
    mapping(uint256 => Transfer) public transfers;       // Mapeo de transfers por ID
    mapping(uint256 => User) public users;               // Mapeo de users por ID
    mapping(address => uint256) public addressToUserId;  // Mapeo de direcciones a IDs de usuario

    // eventos para los tokens, transfers y users
    event TokenCreated(uint256 indexed tokenId, address indexed creator, string name, uint256 totalSupply); // Evento de creación de token
    event TransferRequested(uint256 indexed transferId, address indexed from, address indexed to, uint256 tokenId, uint256 amount); // Evento de solicitud de transferencia
    event TransferAccepted(uint256 indexed transferId); // Evento de aceptación de transferencia
    event TransferRejected(uint256 indexed transferId); // Evento de rechazo de transferencia
    event UserRoleRequested(address indexed user, string role); // Evento de solicitud de rol de usuario
    event UserStatusChanged(address indexed user, UserStatus status); // Evento de cambio de estado de usuario

    constructor() {
        admin = msg.sender; // Establece el administrador del contrato como el creador del contrato
    }   
    
    // --- Modificadores (Modifiers) ---
    // Los modificadores son código reutilizable que se puede añadir a las funciones para
    // verificar condiciones (permisos, estados, etc.) antes de que se ejecuten.

    /**
     * @dev Verifica que quien llama a la función (`msg.sender`) es el dueño o administrador del contrato.
     *      o el propietario del contrato. Si no, revierte la transacción.
     */
    modifier onlyAdmin() {
        if (admin != msg.sender) {
            revert NoAutorizado();
        }
        _; // Este símbolo especial indica que se debe ejecutar el cuerpo de la función que usa el modificador.
    }


    // Gestión de Usuarios
    function requestUserRole(string memory role) public { 
    }
    function changeStatusUser(address userAddress, UserStatus newStatus) public {
    }

    function getUserInfo(address userAddress) public view returns (User memory) {
    }

    function isAdmin(address userAddress) public view returns (bool) {
    }

    // Gestión de Tokens
    function createToken(string memory name, uint totalSupply, string memory features, uint parentId) public {
    }
    function getToken(uint tokenId) public view returns (uint256 id, address creator, string memory name, TokenType tokenType, uint256 totalSupply, string memory features, uint256 parentId, uint256 dateCreated) {
    }

    function getTokenBalance(uint tokenId, address userAddress) public view returns (uint) {
    }

    // Gestión de Transferencias
    function transfer(address to, uint tokenId, uint amount) public { 
    }
    function acceptTransfer(uint transferId) public {
    }
    function rejectTransfer(uint transferId) public {
    }
    function getTransfer(uint transferId) public view returns (Transfer memory) {
    }

    // Funciones auxiliares
    function getUserTokens(address userAddress) public view returns (uint[] memory) {
    }
    function getUserTransfers(address userAddress) public view returns (uint[] memory) {
    }

}