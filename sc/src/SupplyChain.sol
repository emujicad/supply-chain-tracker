// SPDX-License-Identifier: MIT
// Define la versión del compilador de Solidity a utilizar.
// En este caso, es compatible con versiones desde 0.8.30.

pragma solidity 0.8.30;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title SupplyChain
 * @notice Solucion de SupplyChain  para uso educativo: modelo de empresas, productos y facturas.
 * @notice Este contrato inteligente simula una plataforma de SupplyChain básica en la blockchain.
 * @dev Incluye control de acceso por usuario, validaciones, errores personalizados, contadores para IDs automáticos,
 *      eventos para la comunicación con el exterior y funciones de consulta (getters) completas.
 * @dev IMPORTANTE: Este contrato no maneja transferencias de fondos (criptomonedas), solo registra datos.
 *      Está diseñado con fines educativos y del proyecto PFM para mostrar cómo se pueden anidar mappings y estructurar
 *      datos complejos en Solidity, una práctica común para simular bases de datos en la blockchain.
 */

contract SupplyChain  is ReentrancyGuard {

    /* ======================= ERRORES PERSONALIZADOS ======================= */
    /**
    * @notice Lanza si el usuario no tiene aprobación suficiente.
    */
    error NoApproved(); // Se emite cuando una dirección no autorizada intenta ejecutar una función protegida.

    /**
    * @notice Lanza si el nombre proporcionado es inválido o vacío.
    */
    error InvalidName(); // Para entradas de datos no válidas, como un nombre.

    /**
    * @notice Lanza si la dirección es nula o no está permitida.
    */
    error InvalidAddress(); // Si la direccion es invalida o no existe.
 
    /**
    * @notice Lanza si el usuario intenta registrar un rol inválido.
    */
    error InvalidRole(); // Para entradas de roles no válidos.

    /**
    * @notice Acción no realizada por el owner.
    */
    error NoOwner(); // Se emite cuando una dirección no autorizada intenta ejecutar una función protegida que solo el owner o administrador del contrato puede ejecutar. 

    /**
    * @notice No autorizado para Transferir token.
    */   
    error NoTransfersAllowed();

    /**
    * @notice No autorizado para Recibir token.
    */   
    error NoReceiverAllowed();

    /**
    * @notice Acción no autorizada por el rol actual.
    */
    error Unauthorized(); // Se emite cuando una dirección no autorizada intenta ejecutar una función protegida.

    /**
    * @notice Acción emitida cuando el contrado está pausado.
    */
    error ContractPaused(); // Se emite cuando. 

   /**
    * @notice Acción emitida cuando el contrado no está pausado.
    */
    error ContractNotPaused(); // Se emite cuando.

    /**
    * @notice El usuario ya tiene al menos un rol aprobado.
    */
    error ExistingUserWithApprovedRole(); // Si se intenta registrar. 
 
     /**
    * @notice La consulta o acción requiere un Usuario existente.
    */
    error UserDoesNotExist(); // Si se intenta consultar un usuario que no existe. 

     /**
    * @notice La consulta o acción requiere un Id de Usuario existente.
    */
    error InvalidUserId(); // Si se intenta consultar un id de usuario que no existe. 

    /**
    * @notice El usuario ya tiene el rol solicitado.
    */
    error UserWithExistingRole(); // Si se intenta asignar el mismo rol a un usuario ya existente.
 
    /**
    * @notice El total de suministro no es válido (>0).
    */
    error InvalidTotalSupply();
 
    /**
    * @notice La consulta o acción requiere un token existente.
    */
    error TokenDoesNotExist(); 
 
    /**
    * @notice La cantidad debe ser mayor a 0.
    */
    error InvalidAmount(); 

    /**
    * @notice La cantidad debe ser mayor a 0.
    */
    error InsufficientBalance(uint256 senderBalance, uint256 amount); 

    /**
    * @notice El token padre solicitado no existe.
    */
    error ParentTokenDoesNotExist(); 

    /**
    * @notice La consulta o acción requiere que la transferencia existenta.
    */
    error TransferDoesNotExist(); 

    /**
    * @notice Transferencia debe estar en Pendiente.
    */
    error TransferNotPending(); 

    /* ======================= ENUMS ======================= */
    /**
    * @notice Enum para roles de pausabilidad, básico/pausador.
    */
    enum PauseRole {
        None,
        Pauser
    }

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
        Rejected,    //Valor 2
        Cancelled   //Valor 3
    }

    /**
    * @notice Enum para diferenciar tokens de materia prima y producto terminado.
    */ 
    enum TokenType {
        RowMaterial,       //Valor 0
        FinishedProduct    //Valor 1
    }

    /* ======================= STRUCTS ======================= */

    /**
    * @notice Representa los datos principales de un usuario en la plataforma.
    * @dev La relación entre usuario y dirección se gestiona vía mappings addressToUserId y users.
    */
   struct User {
        uint256 id;
        address userAddress;
        UserRole role;
        UserStatus status;
    }

    /**
    * @notice Estructura para registrar activos de la cadena de suministro.
    * @dev Incluye campo de balances por dirección.
    */
    struct Token {
        uint256 id;        // Token ID
        address creator;   // Dirección del creador del token
        string name;       // Nombre del token
        TokenType tokenType; // Tipo de token 
        uint256 totalSupply; // Suministro o cantidad total del token
        string features;   // Características del token (JSON string)
        uint256 parentId;  // ID del token padre (si es un token hijo) , 0 si es un token de materia prima y !=0 si es producto terminado
        uint256 dateCreated;    // Fecha de creación del token
        mapping(address => uint256) balance;    // Mapeo de balances por dirección
    }

    /**
    * @notice Modelo para transferencias dentro de la plataforma.
    */
    struct Transfer {
        uint256 id;       // ID de la transferencia
        address from;     // Dirección del remitente
        address to;       // Dirección del destinatario
        uint256 tokenId;  // ID del token a transferir
        uint256 dateCreated; // Fecha de creación de la transferencia
        uint256 amount;   // Cantidad de tokens transferidos
        TransferStatus status;
    }
 
    address public owner;   // Dirección del administrador/dueño del contrato
    // Declarar variable para candidato a nuevo owner
    address private pendingOwner;

    // Contadores para los ids de los usurios, tokens y transferencias
    uint256 public nextUserId = 1;       // ID del próximo usuario
    uint256 public nextTokenId = 1;     // ID del próximo token
    uint256 public nextTransferId = 1;   // ID de la próxima transferencia
    

    // mapping para asignar roles de pausabilidad a direcciones
    mapping(address => PauseRole) private pauseRoles;

    // mapping para usuarios, los tokens y las transferencias

    /**
     * @notice Almacena todas los usuarios registrados por su id.
     * @dev `mapping(uint256 => User)`: Asocia una el id del usuario (clave)
     *      con la estructura de datos `User` (el valor). Es `private` para controlar el acceso.
     */

    mapping(uint256 => User) public users;               // Mapeo de users por ID
      /**
     * @notice Almacena todas los id de usuario registrados por su direcciones de las billeteras.
     * @dev `mapping(address => uint256)`: Asocia una dirección de billetera (la clave) del User
     *      con el id asignado al `User` (el valor). Es `private` para controlar el acceso.
     */

    mapping(address => uint256) public addressToUserId;  // Mapeo de direcciones a IDs de usuario

    mapping(uint256 => Token) public tokens;             // Mapeo de tokens por ID
    mapping(address => uint) public userTokenCount;
    
    mapping(uint256 => Transfer) public transfers;       // Mapeo de transfers por ID

    // Estado de pausa
    bool private paused;

    /* ======================= EVENTOS ======================= */

    /**
     * @notice Evento para pausar el contrato.
     */
    // Evento para emitir cuando cambie el estado de pausa
    event Paused(address account);

    /**
    * @notice Evento para reanudar el contrato.
    */
    event Unpaused(address account);

    /**
    * @notice Evento al asignar roles especiales de pausador o revocar.
    */
    // Evento para asignar o revocar rol Pauser
    event PauseRoleChanged(address indexed account, PauseRole role);

    /**
    * @notice Evento de asignación inicial de ownership.
    */
    event AssignInitialContractOwner(address indexed initialContractOwner);

    /**
    * @notice Evento al iniciar la transferencia de ownership.
    */
    event OwnershipTransferInitiated(address indexed previousOwner, address indexed newContractOwner);
    /**
    * @notice Evento cuando la transferencia de ownership es confirmada/completada.
    */
    event OwnershipTransferred(address indexed previousOwner, address indexed newContractOwner);

    // eventos para los users tokens y transfers
 
    /**
    * @notice Evento al solicitar un nuevo rol de usuario.
    */
    event UserRoleRequested(address indexed user, UserRole role); // Evento de solicitud de rol de usuario

    /**
    * @notice Evento por cambio de estado de usuario.
    */
    event UserStatusChanged(address indexed user, UserStatus oldStatus, UserStatus newStatus);


    /**
    * @notice Evento cuando se crea un nuevo token.
    */
    event TokenCreated(uint256 indexed tokenId, address indexed creator, string name, TokenType tokenType, uint256 totalSupply, uint256 parentId);

    /**
    * @notice Evento que representa una solicitud de transferencia.
    */
    event TransferRequested(uint256 indexed transferId, address indexed from, address indexed to, uint256 tokenId, uint256 amount); // Evento de solicitud de transferencia
 
     /**
    * @notice Evento ante la cancelacion de una transferencia.
    */
    event TransferCancelled(uint256 indexed transferId); // Evento de cancellación de transferencia

    /**
    * @notice Evento ante la aceptación de una transferencia.
    */
    event TransferAccepted(uint256 indexed transferId); // Evento de aceptación de transferencia
    /**
    * @notice Evento cuando una transferencia ha sido rechazada.
    */
    event TransferRejected(uint256 indexed transferId); // Evento de rechazo de transferencia

    event TransferProcessed(uint indexed transferId, address from, address to, TransferStatus status, uint256 amount);

    constructor() {
        owner = msg.sender; // Establece el administrador del contrato como el creador del contrato
        emit AssignInitialContractOwner(owner);
    }   
    
    /* ======================= MODIFICADORES ======================= */

    // Los modificadores son código reutilizable que se puede añadir a las funciones para
    // verificar condiciones (permisos, estados, etc.) antes de que se ejecuten.

    /**
    * @dev Solo permite acceso al administrator/dueño actual del contrato.
    * @dev Verifica que quien llama a la función (`msg.sender`) es el dueño o administrador del contrato.
    *      Si no, revierte la transacción.
    */
    modifier onlyOwner() {
        //require(owner == msg.sender, "No es el administrador o dueno del contrato");
        if (owner != msg.sender) revert NoOwner();
        _; // Este símbolo especial indica que se debe ejecutar el cuerpo de la función que usa el modificador.
    }

    /* ======================= FUNCIONES PRINCIPALES:  ======================= */

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

    receive() external payable {
    revert("Este contrato no acepta ETH");
    }

    fallback() external payable {
    revert("Funcion no soportada");
    }
}