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
    * @dev Solo permite acceso a usuarios con rol Producer o Factory y status Approved.
    */
    modifier onlyTokenCreators() {
        User storage user = users[addressToUserId[msg.sender]];
        //require(msg.sender != address(0), "Direccion invalida para hacer esta solicitud");
        //require(msg.sender != owner, "El dueno del contrato no puede crear tokens");
        if (msg.sender == owner) revert Unauthorized();

        //require((user.role == UserRole.Producer || user.role == UserRole.Factory) && user.status == UserStatus.Approved, "Sin permisos para crear tokens");  
        if (!((user.role == UserRole.Producer || user.role == UserRole.Factory) && user.status == UserStatus.Approved)) revert Unauthorized();

        _; // Este símbolo especial indica que se debe ejecutar el cuerpo de la función que usa el modificador.
    }

    /**
    * @dev Modificador que restringe la ejecución solo a usuarios con estado Approved
    *      y rol Producer, Factory o Retailer. Usado para controlar permisos en funciones
    *      de transferencia de tokens (emisión y envío).
    */
    modifier onlyTransfersAllowed() {
        User storage user = users[addressToUserId[msg.sender]];
        //require(user.status == UserStatus.Approved && (user.role == UserRole.Producer || user.role == UserRole.Factory || user.role == UserRole.Retailer), "No autorizado para transferir tokens");
        if (!(user.status == UserStatus.Approved && (user.role == UserRole.Producer || user.role == UserRole.Factory || user.role == UserRole.Retailer))) revert NoTransfersAllowed();
        _;
    }

    /**
    * @dev Modificador que restringe la ejecución solo a usuarios con estado Approved
    *      y rol Factory, Retailer o Consumer. Usado para controlar permisos en funciones
    *      que aceptan o rechazan tokens recibidos en transferencias.
    */
    modifier onlyReceiverAllowed() {
        User storage user = users[addressToUserId[msg.sender]];
        if (!(user.status == UserStatus.Approved && (user.role == UserRole.Factory || user.role == UserRole.Retailer || user.role == UserRole.Consumer))) revert NoReceiverAllowed();
        //require(user.status == UserStatus.Approved && (user.role == UserRole.Factory || user.role == UserRole.Retailer || user.role == UserRole.Consumer), "No autorizado para recibir o rechazar tokens");
        _;
    }

    /**
    * @dev Solo permite acceso al administrator/dueño actual del contrato.
    */
    modifier onlyOwner() {
        //require(owner == msg.sender, "No es el administrador o dueno del contrato");
        if (owner != msg.sender) revert NoOwner();
        _; // Este símbolo especial indica que se debe ejecutar el cuerpo de la función que usa el modificador.
    }

    /**
     * @dev Solo permite acceso a usuarios con rol de pausador o dueño/administrador.
    */
    // Modificador para restringir funciones solo a pausadores autorizados
    modifier onlyPauser() {
        //require(pauseRoles[msg.sender] == PauseRole.Pauser || msg.sender == owner, "No autorizado para pausar");
        if (pauseRoles[msg.sender] != PauseRole.Pauser && msg.sender != owner) revert Unauthorized();
        _;
    }

    /**
    * @dev Restringe ejecución si el contrato está pausado.
    */
    // Modificador para funciones que solo pueden ejecutarse si el contrato NO está pausado
    modifier whenNotPaused() {
        //require(!paused, "Contrato pausado");
        if (paused) revert ContractPaused();
        _;
    }

    /**
    * @dev Restringe ejecución si el contrato no está pausado (opcional).
    */
    // Modificador para funciones que solo pueden ejecutarse si el contrato está pausado (opcional)
    modifier whenPaused() {
        //require(paused, "Contrato no esta pausado");
        if (!paused) revert ContractNotPaused();
        _;
    }

/* ======================= FUNCIONES PRINCIPALES: ejemplos ======================= */

    /**
    * @notice Asigna o revoca el rol Pauser a una dirección, controlando autorización para pausar/reanudar.
    * @param account Dirección a la que se asignará el rol.
    * @param role El rol a asignar (None o Pauser).
    */
    function setPauseRole(address account, PauseRole role) external onlyOwner {
        pauseRoles[account] = role;
        emit PauseRoleChanged(account, role);
    }

    /**
    * @notice Pausa todas las funciones críticas del contrato.
    * @dev Solo el owner o usuarios con rol Pauser pueden pausar si el contrato no está ya pausado.
    */
    // Función para pausar el contrato (solo el owner)
    function pause() external onlyPauser whenNotPaused {
        paused = true;
        emit Paused(msg.sender);
    }

    /**
    * @notice Reanuda la operación normal del contrato si está pausado.
    * @dev Solo el owner o usuarios con rol Pauser pueden reanudar si el contrato estaba pausado.
    */
    // Función para reanudar el contrato (solo el owner)
    function unpause() external onlyPauser whenPaused {
        paused = false;
        emit Unpaused(msg.sender);
    }

    /**
    * @notice Consulta el estado actual de pausabilidad del contrato.
    * @return bool True si el contrato está pausado, false en caso contrario.
    */
    function isPaused() public view returns (bool) {
        return paused;
    }

    /**
    * @notice Inicializa la transferencia de ownership a otra dirección.
    * @param newOwner Dirección del nuevo propietario candidato.
    * @dev Solo puede ser llamada por el owner y requiere contrato activo (no pausado).
    */
    function initiateOwnershipTransfer(address newOwner) external onlyOwner whenNotPaused {
        //require(newOwner != address(0), "Nueva direccion invalida");
        if (newOwner == address(0)) revert InvalidAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferInitiated(owner, newOwner);
    }

    /**
    * @notice El candidato a owner debe aceptar para completar la transferencia de ownership.
    * @dev Solo llamable por el address pendingOwner previamente configurado.
    */
    function acceptOwnership() external whenNotPaused {
        //require(msg.sender == pendingOwner, "Solo nuevo owner puede aceptar");
        if (msg.sender != pendingOwner) revert Unauthorized();
        address oldOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(oldOwner, owner);
    }

    /**
     * @notice Getter público para ver quién es el pendingOwner actual.
     * @return Dirección del usuario que debe aceptar la transferencia de ownership.
     */
    function getPendingOwner() public view returns (address) {
        return pendingOwner;
    }

    // Gestión de Usuarios
    // Gestión de Usuarios
    /**
    * @notice Función para que usuarios, excepto el owner, soliciten un rol en la plataforma.
    * @param role Role solicitado.
    */
    function requestUserRole(UserRole role) external whenNotPaused { 
        uint256 userId;

        //if (msg.sender == address(0) || owner == msg.sender ) revert InvalidAddress();
        if (owner == msg.sender ) revert InvalidAddress();
        //if (bytes(role).length == 0) revert InvalidEntry("role");
        if (uint(role) > 3 ) revert InvalidRole();

        // `storage` crea una referencia a la variable en el almacenamiento de la blockchain.
        // Modificar `u` modifica directamente el estado del contrato.

        userId = addressToUserId[msg.sender];
        bool userExists = (userId != 0);
        if ( userExists) {
            
            User storage user = users[userId];

            //if (uint(role) ==  users[nextUserId].role) {
            if (uint(role) ==  uint(user.role)) {
                revert UserWithExistingRole();
            }

            if  (user.status == UserStatus.Approved) {
                revert ExistingUserWithApprovedRole();
            }

            if  (user.status != UserStatus.Pending) {
                user.status = UserStatus.Pending;
            }
            user.role = role;
            emit UserRoleRequested(msg.sender, role);
        }
            
        else{
            //crea un nuevo User con el ID actual, la dirección que llamó a la función (msg.sender), el rol recibido como parámetro, y un estado definido Pending
            User storage user = users[nextUserId];
            user.id = nextUserId;
            user.userAddress = msg.sender;
            user.role = role;
            user.status = UserStatus.Pending;

            addressToUserId[msg.sender] = nextUserId; //establece la relación entre la dirección y el ID del usuario. 
            // Incrementar el ID para el próximo usuario
            
            unchecked {
                nextUserId++;
            }
            emit UserRoleRequested(msg.sender, role);
        }
    }

    /**
    * @notice Solo el owner puede cambiar el estado de un usuario.
    * @param userAddress Dirección del usuario.
    * @param newStatus Estado a asignar.
    */
    function changeStatusUser(address userAddress, UserStatus newStatus) external onlyOwner whenNotPaused {
        //require(addressToUserId[userAddress] != 0, "Usuario no existe");
        if (addressToUserId[userAddress] == 0) revert UserDoesNotExist();

        if (msg.sender == address(0) || owner == userAddress ) revert InvalidAddress();
        User storage user = users[addressToUserId[userAddress]]; //establece la relación entre la dirección y el ID del usuario.

        UserStatus oldStatus = user.status;
        user.status = newStatus;
        emit UserStatusChanged(userAddress, oldStatus, newStatus); 
    }

    /**
    * @notice Devuelve información completa de un usuario registrado.
    * @param userAddress Dirección del usuario consultado.
    * @return user Información del usuario.
    */
    function getUserInfo(address userAddress) public view returns (User memory) {
        if (msg.sender == address(0) || owner == userAddress ) revert InvalidAddress();
        return users[addressToUserId[userAddress]];
    }

    /**
    * @notice Devuelve información de un usuario registrado a partir de su ID.
    * @param userId Identificador del usuario.
    * @return User Estructura con datos del usuario.
    * @dev Requiere que el ID sea válido (mayor que 0 y menor que el próximo ID).
    */
    function getUserInfoById(uint userId) public view returns (User memory) {
        //require(userId > 0 && userId < nextUserId, "User ID invalido");
        if (userId == 0 || userId >= nextUserId) revert InvalidUserId();
        return users[userId];
    }

    /**
    * @notice Devuelve el total de usuarios registrados en el contrato.
    * @return uint Cantidad total de usuarios (ID máximo asignado menos 1).
    */
    function getTotalUsers() public view returns (uint) {
        return nextUserId - 1;
    }

    /**
    * @notice Devuelve si el usuario dado es admin del contrato.
    * @param userAddress Dirección a consultar.
    * @return True si es owner, false en caso contrario.
    */
    function isAdmin(address userAddress) public view returns (bool) {
        //require(userAddress != address(0), "Direccion invalida para hacer esta solicitud");
        if (userAddress == address(0)) revert InvalidAddress();

        if (owner == userAddress ) {
            return true;
        }
        else {
            return false;
        }
    }

    // Gestión de Tokens
   /**
     * @notice Crea un nuevo token, sea materia prima o producto terminado.
     * @param name Nombre del token, obligatorio no vacío.
     * @param tokenType Tipo de token (RowMaterial o FinishedProduct).
     * @param totalSupply Cantidad total disponible para el token. Debe ser mayor que cero.
     * @param features Características adicionales en string JSON.
     * @param parentId ID del token padre. 0 si es materia prima, distinto de 0 para producto terminado.
     * @dev Lanza error si el padre no existe o si las validaciones fallan.
     * @dev Incrementa contador de tokens y actualiza balance inicial del creador.
     */
    function createToken(string memory name, TokenType tokenType, uint totalSupply, string memory features, uint parentId) external onlyTokenCreators whenNotPaused {
        if (bytes(name).length == 0) revert InvalidName();
        if (totalSupply == 0) revert InvalidTotalSupply();

        if (parentId != 0 && tokens[parentId].id == 0) {
                revert ParentTokenDoesNotExist();
        }

        Token storage newToken = tokens[nextTokenId];
        newToken.id = nextTokenId;
        newToken.creator = msg.sender;
        newToken.name = name;
        newToken.tokenType = tokenType;
        newToken.totalSupply = totalSupply;
        newToken.features = features;
        newToken.parentId = parentId;
        newToken.dateCreated = block.timestamp;
        newToken.balance[msg.sender] = totalSupply;

        emit TokenCreated(nextTokenId, msg.sender, name, tokenType, totalSupply, parentId);

        unchecked {
            nextTokenId++;
        }
        userTokenCount[msg.sender]++;
    }

    /**
     * @notice Consulta detalles completos de un token específico.
     * @param tokenId ID del token a consultar.
     * @return id ID del token.
     * @return creator Dirección que creó el token.
     * @return name Nombre del token.
     * @return tokenType Tipo del token.
     * @return totalSupply Suministro total del token.
     * @return features Características en JSON.
     * @return parentId Token padre relacionado.
     * @return dateCreated Timestamp de creación.
     * @dev Requiere que el token exista.
     */
    function getToken(uint tokenId) public view returns (uint256 id, address creator, string memory name, TokenType tokenType, uint256 totalSupply, string memory features, uint256 parentId, uint256 dateCreated) {
    Token storage token = tokens[tokenId];
    if (token.id == 0) revert TokenDoesNotExist();
        return (token.id, token.creator, token.name, token.tokenType, token.totalSupply, token.features, token.parentId, token.dateCreated);
    }

    /**
    * @notice Devuelve el total de tokens registrados en el contrato.
    * @return uint Cantidad total de tokens (ID máximo asignado menos 1).
    */
    function getTotalTokens() public view returns (uint) {
        return nextTokenId - 1;
    }

    /**
     * @notice Consulta el balance de un usuario para un token específico.
     * @param tokenId ID del token.
     * @param userAddress Dirección del usuario.
     * @return uint Balance del usuario para ese token.
     * @dev Requiere dirección válida y token existente.
     */
    function getTokenBalance(uint tokenId, address userAddress) public view returns (uint) {
        //require(userAddress != address(0), "Direccion invalida para hacer esta solicitud");
        if (userAddress == address(0)) revert InvalidAddress();
        //require(userAddress != owner, "Owner no puede solicitar balance de ningún token");
        Token storage token = tokens[tokenId];
        if (token.id == 0) revert TokenDoesNotExist();
        return token.balance[userAddress];
    }

    // Gestión de Transferencias

    /**
    * @notice Solicita una transferencia de una cantidad específica de un token a otro usuario.
    * @param to Dirección destinataria de la transferencia.
    * @param tokenId ID del token a transferir.
    * @param amount Cantidad de tokens a transferir.
    * @dev Solo usuarios con balance suficiente pueden hacer la transferencia, y solo usuarios aprobados y con rol adecuado.
    * @dev Se crea una transferencia en estado Pending, su aceptación o rechazo se debe manejar con funciones específicas.
    */
    function transfer(address to, uint tokenId, uint amount) external whenNotPaused onlyTransfersAllowed nonReentrant{

        //require(to != address(0), "Direccion destino invalida");
        //require(amount > 0, "Cantidad debe ser mayor que cero");
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert InvalidAmount();
        
        Token storage token = tokens[tokenId];
        if (token.id == 0) revert TokenDoesNotExist();

        uint256 senderBalance = token.balance[msg.sender];
        //require(senderBalance >= amount, "Saldo insuficiente para transferencia");
        if (senderBalance < amount) revert InsufficientBalance(senderBalance, amount);

        // Disminuir balance del remitente inmediatamente para evitar doble gasto
        token.balance[msg.sender] = senderBalance - amount;

        // Crear nueva transferencia tipo pending
        Transfer storage transferItem = transfers[nextTransferId];
        transferItem.id = nextTransferId;
        transferItem.from = msg.sender;
        transferItem.to = to;
        transferItem.tokenId = tokenId;
        transferItem.amount = amount;
        transferItem.dateCreated = block.timestamp;
        transferItem.status = TransferStatus.Pending;

        emit TransferRequested(nextTransferId, msg.sender, to, tokenId, amount);

        unchecked {
            nextTransferId++;
        }
    }

    /**
    * @notice Acepta una transferencia pendiente, completando el movimiento de tokens entre usuarios.
    * @param transferId ID de la transferencia a aceptar.
    * @dev Solo puede ser llamada por el destinatario de la transferencia..
    *      Actualiza balances y estado de transferencia.
    *      Emite el evento TransferAccepted.
    *      Requiere que el contrato no esté pausado.
    */
    function acceptTransfer(uint transferId) external whenNotPaused onlyReceiverAllowed nonReentrant{

        //require(transfers[transferId].id != 0, "Transferencia inexistente");
        if (transfers[transferId].id == 0) revert TransferDoesNotExist();

        Transfer storage transferItem = transfers[transferId];

        //require(transferItem.status == TransferStatus.Pending, "Transfer not pending");
        //require(transferItem.to == msg.sender, "Solo receptor puede aceptar transferencias");
        if (transferItem.status != TransferStatus.Pending) revert TransferNotPending();
        if (transferItem.to != msg.sender) revert Unauthorized();
        
        Token storage token = tokens[transferItem.tokenId];
        
        // Incrementar balance del receptor
        token.balance[transferItem.to] += transferItem.amount;

        // 🔹 ACTUALIZAR CONTADORES DE TOKENS POR USUARIO 🔹
        // Si el emisor ya no tiene saldo de este token, reduce su contador
        if (token.balance[transferItem.from] == 0 && userTokenCount[transferItem.from] > 0) {
            userTokenCount[transferItem.from]--;
        }

        // Si el receptor no tenía este token antes, incrementa su contador
        if (token.balance[transferItem.to] == transferItem.amount) {
            userTokenCount[transferItem.to]++;
        }

        // Marcar transferencia como aceptada
        transferItem.status = TransferStatus.Accepted;
        // Emitir eventos
        emit TransferAccepted(transferId);
        emit TransferProcessed(transferId, transferItem.from, transferItem.to, transferItem.status, transferItem.amount);
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