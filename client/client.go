package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"bytes"
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	UUiD       uuid.UUID
	Username   string
	Salt       []byte
	PassA      []byte
	PassB      []byte
	EncPrivKey []byte
	EncSignKey []byte
	PubKey     userlib.PublicKeyType
	privateKey userlib.PrivateKeyType
	signKey    userlib.PrivateKeyType

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	Content   []byte
	Creator   userlib.UUID
	PrevBlock userlib.UUID
}

type SignedFile struct {
	FileData  []byte
	Signature []byte
}

type FilePointer struct { //Gets encrypted with Editor's public key
	F_owner uuid.UUID
	RandKey []byte
}

type BlockPointer struct { //Gets encrypted with RandKey
	BlockiD uuid.UUID
	SymKey  []byte
}

type AccessList struct {
	Fname    uuid.UUID   //Local name for this file
	Children []uuid.UUID //Everyone they have directly shared with
}

type Invitation struct {
	F_owner uuid.UUID
	RandKey []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

type Err int

func (e Err) Error() string {
	if e == 1 {
		return "Username cannot be empty"
	}
	if e == 2 {
		return "Username is taken"
	}
	if e == 3 {
		return "Error with built-in function"
	}
	if e == 4 {
		return "Username does not exist"
	}
	if e == 5 {
		return "Incorrect credentials"
	}
	if e == 6 {
		return "Tampering Detected"
	}
	if e == 7 {
		return "SymEnc Sizing Issues"
	}
	if e == 8 {
		return "File Not Found"
	}
	return ""
}

// Used Chat GPT to create this helper function
func reverseBytes(input []byte) []byte {
	for i, j := 0, len(input)-1; i < j; i, j = i+1, j-1 {
		input[i], input[j] = input[j], input[i]
	}
	return input
}

func InitUser(username string, password string) (userdataptr *User, err error) {

	var userdata User
	if username == "" {
		return &userdata, Err(1)
	}

	user_n, E := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if E != nil {
		return &userdata, Err(3)
	}

	_, bol := userlib.DatastoreGet(user_n)
	if bol {
		return &userdata, Err(2)
	}

	U := uuid.New()
	salt := userlib.RandomBytes(16)

	pubKey, prKey, E := userlib.PKEKeyGen()
	if E != nil {
		return &userdata, Err(3)
	}

	sKey, vKey, E := userlib.DSKeyGen()
	if E != nil {
		return &userdata, Err(3)
	}

	userlib.KeystoreSet("pk"+U.String(), pubKey)
	userlib.KeystoreSet("vk"+U.String(), vKey)

	HPass := userlib.Argon2Key([]byte(password), salt, 16)

	pSave, E := json.Marshal(prKey)
	if E != nil {
		return &userdata, Err(3)
	}

	sSave, E := json.Marshal(sKey)
	if E != nil {
		return &userdata, Err(3)
	}

	if len(HPass) != 16 || len([]byte(U.String())) < 16 {
		fmt.Println("c2")
		return &userdata, Err(7)
	}
	priv := userlib.SymEnc(HPass, []byte(U.String())[:16], pSave)
	sign := userlib.SymEnc(HPass, []byte(U.String())[:16], sSave)

	A, E := userlib.PKEEnc(pubKey, HPass)
	if E != nil {
		return &userdata, Err(3)
	}

	B, E := userlib.PKEEnc(pubKey, userlib.Argon2Key(HPass, salt, 16))
	if E != nil {
		return &userdata, Err(3)
	}

	userdata.UUiD = U
	userdata.Username = username
	userdata.Salt = salt
	userdata.PassA = A
	userdata.PassB = B
	userdata.PubKey = pubKey
	userdata.EncPrivKey = priv
	userdata.EncSignKey = sign

	toSave, E := json.Marshal(userdata)
	if E != nil {
		return &userdata, Err(3)
	}

	userlib.DatastoreSet(user_n, toSave)

	userdata.privateKey = prKey
	userdata.signKey = sKey

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	user_n, E := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if E != nil {
		return &userdata, Err(3)
	}

	data, found := userlib.DatastoreGet(user_n)
	if !found {
		fmt.Println("E1")
		return &userdata, Err(2)
	}

	E = json.Unmarshal(data, &userdata)
	if E != nil {
		fmt.Println("E2")
		return nil, Err(6)
	}

	salt := userdata.Salt
	PassA := userdata.PassA
	PassB := userdata.PassB
	priv := userdata.EncPrivKey
	sign := userdata.EncSignKey

	HPass := userlib.Argon2Key([]byte(password), salt, 16)

	if len(HPass) != 16 || len(priv) < 16 || len(sign) < 16 {
		fmt.Println("E4")
		return nil, Err(7)
	}

	pSave := userlib.SymDec(HPass, priv)
	sSave := userlib.SymDec(HPass, sign)

	var prKey userlib.PrivateKeyType
	var sKey userlib.PrivateKeyType

	E = json.Unmarshal(pSave, &prKey)
	if E != nil {
		return nil, Err(3)
	}
	E = json.Unmarshal(sSave, &sKey)
	if E != nil {
		return nil, Err(3)
	}

	HPTest, E := userlib.PKEDec(prKey, PassA)
	if E != nil {
		return nil, Err(3)
	}
	BTest := userlib.Argon2Key(HPTest, salt, 16)
	decB, E := userlib.PKEDec(prKey, PassB)
	if E != nil {
		return nil, Err(3)
	}

	if !bytes.Equal(BTest, decB) {
		fmt.Println("E5")
		return nil, Err(6)
	}

	if !bytes.Equal(HPass, HPTest) {
		fmt.Println("E6")
		return nil, Err(5)
	}

	userdata.privateKey = prKey
	userdata.signKey = sKey

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	f_editor, E := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.UUiD.String()))[:16])
	if E != nil {
		return Err(3)
	}

	var f_owner uuid.UUID
	var RandKey []byte
	var symKey []byte

	info, bol := userlib.DatastoreGet(f_editor)

	found := false

	if bol {
		found = true
		fpdata, E := userlib.PKEDec(userdata.privateKey, info)
		if E != nil {
			return Err(3)
		}
		var filepointer FilePointer
		E = json.Unmarshal(fpdata, &filepointer)
		if E != nil {
			return Err(3)
		}

		f_owner = filepointer.F_owner
		RandKey = filepointer.RandKey

		info, bol := userlib.DatastoreGet(f_owner)
		if !bol {
			return Err(3)
		}

		if len(RandKey) != 16 || len(info) < 16 {
			fmt.Println("case 1")
			return Err(7)
		}
		bpdata := userlib.SymDec(RandKey, info)
		var blockpointer BlockPointer
		E = json.Unmarshal(bpdata, &blockpointer)
		if E != nil {
			return Err(3)
		}

		symKey = blockpointer.SymKey
		return nil
	} else {
		RandKey, E = userlib.HashKDF(userdata.EncPrivKey[:16], userlib.RandomBytes(16))
		if E != nil {
			return Err(3)
		}
		RandKey = RandKey[:16]

		f_owner, E = uuid.FromBytes(userlib.Hash(append([]byte(f_editor.String()), []byte(userdata.UUiD.String())...))[:16])
		if E != nil {
			return Err(3)
		}

		symKey, E = userlib.HashKDF(userdata.EncPrivKey[:16], userlib.RandomBytes(16))
		if E != nil {
			return Err(3)
		}
		symKey = symKey[:16]
	}

	BlockiD := uuid.New()

	if len(symKey) < 16 || len([]byte(userdata.UUiD.String())) < 16 {
		fmt.Println("case 2")
		return Err(7)
	}
	cont := userlib.SymEnc(symKey, []byte(userdata.UUiD.String())[:16], content)

	var file File
	file.Content = cont
	file.Creator = userdata.UUiD
	file.PrevBlock = f_owner

	fBlock, E := json.Marshal(file)
	if E != nil {
		return Err(3)
	}
	signature, E := userlib.DSSign(userdata.signKey, fBlock)
	if E != nil {
		return Err(3)
	}
	var sigFile SignedFile
	sigFile.FileData, sigFile.Signature = fBlock, signature
	toSave, E := json.Marshal(sigFile)
	if E != nil {
		return Err(3)
	}
	if len([]byte(f_owner.String())) < 16 || len([]byte(userdata.UUiD.String())) < 16 {
		fmt.Println("case 5")
		return Err(7)
	}
	contentBytes := userlib.SymEnc([]byte(f_owner.String())[:16], []byte(userdata.UUiD.String())[:16], toSave)
	userlib.DatastoreSet(BlockiD, contentBytes)

	var bpointer BlockPointer
	bpointer.BlockiD = BlockiD
	bpointer.SymKey = symKey
	toSave, E = json.Marshal(bpointer)
	if E != nil {
		return Err(3)
	}
	if len(RandKey) != 16 || len([]byte(userdata.UUiD.String())) < 16 {
		fmt.Println("case 3")
		return Err(7)
	}
	contentBytes = userlib.SymEnc(RandKey, []byte(userdata.UUiD.String())[:16], toSave)
	userlib.DatastoreSet(f_owner, contentBytes)

	if found {
		return nil
	}

	var fpointer FilePointer
	fpointer.F_owner = f_owner
	fpointer.RandKey = RandKey
	//------------------
	toSave, E = json.Marshal(fpointer)
	if E != nil {
		return Err(3)
	}
	contentBytes, E = userlib.PKEEnc(userdata.PubKey, toSave)
	if E != nil {
		return Err(3)
	}
	userlib.DatastoreSet(f_editor, contentBytes)

	var accessList AccessList
	accessList.Fname = f_owner
	toSave, E = json.Marshal(accessList)

	// can you change it so that there is a deterministic location for the access list?
	// like filename + UUID + AL + random number or something like that

	if E != nil {
		return Err(3)
	}
	if len(RandKey) != 16 || len([]byte(userdata.UUiD.String())) < 16 {
		fmt.Println("case 4")
		return Err(7)
	}
	contentBytes = userlib.SymEnc(RandKey, []byte(userdata.UUiD.String())[:16], toSave)
	Lbytes, E := userlib.HashKDF(userdata.EncPrivKey[:16], []byte("AccessList"))
	if E != nil {
		return Err(3)
	}
	privateUUID, E := uuid.FromBytes(Lbytes[:16])
	if E != nil {
		return Err(3)
	}
	userlib.DatastoreSet(privateUUID, contentBytes)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	f_editor, E := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.UUiD.String()))[:16])
	if E != nil {
		fmt.Println("A1")
		return Err(3)
	}

	info, bol := userlib.DatastoreGet(f_editor)
	if !bol {
		fmt.Println("A2")
		return Err(8)
	}

	var f_owner uuid.UUID
	var RandKey []byte
	var oldBlockiD uuid.UUID
	var symKey []byte
	BlockiD := uuid.New()

	fpdata, E := userlib.PKEDec(userdata.privateKey, info)
	if E != nil {
		fmt.Println("A3")
		return Err(3)
	}
	var filepointer FilePointer
	E = json.Unmarshal(fpdata, &filepointer)
	if E != nil {
		fmt.Println("A4")
		return Err(3)
	}

	f_owner = filepointer.F_owner
	RandKey = filepointer.RandKey

	//-------

	info, bol = userlib.DatastoreGet(f_owner)
	if !bol {
		fmt.Println("A5")
		return Err(3)
	}

	if len(RandKey) != 16 || len(info) < 16 {
		fmt.Println("A6")
		return Err(7)
	}
	bpdata := userlib.SymDec(RandKey, info)
	var blockpointer BlockPointer
	E = json.Unmarshal(bpdata, &blockpointer)
	if E != nil {
		fmt.Println("A7 ", E)
		return Err(3)
	}

	symKey = blockpointer.SymKey
	oldBlockiD = blockpointer.BlockiD

	if len(symKey) != 16 || len([]byte(userdata.UUiD.String())) < 16 {
		fmt.Println("A8")
		return Err(7)
	}
	cont := userlib.SymEnc(symKey, []byte(userdata.UUiD.String())[:16], content)

	var file File
	file.Content = cont
	file.Creator = userdata.UUiD
	file.PrevBlock = oldBlockiD

	fBlock, E := json.Marshal(file)
	if E != nil {
		fmt.Println("A14")
		return Err(3)
	}
	signature, E := userlib.DSSign(userdata.signKey, fBlock)
	if E != nil {
		fmt.Println("A9")
		return Err(3)
	}
	var sigFile SignedFile
	sigFile.FileData, sigFile.Signature = fBlock, signature
	toSave, E := json.Marshal(sigFile)
	if E != nil {
		fmt.Println("A10")
		return Err(3)
	}
	if len([]byte(f_owner.String())) < 16 || len([]byte(userdata.UUiD.String())) < 16 {
		fmt.Println("A11")
		return Err(7)
	}
	contentBytes := userlib.SymEnc([]byte(f_owner.String())[:16], []byte(userdata.UUiD.String())[:16], toSave)
	userlib.DatastoreSet(BlockiD, contentBytes)

	blockpointer.BlockiD = BlockiD
	toSave, E = json.Marshal(blockpointer)
	if E != nil {
		fmt.Println("A12")
		return Err(3)
	}
	if len(RandKey) != 16 || len([]byte(userdata.UUiD.String())) < 16 {
		fmt.Println("c3")
		fmt.Println("A13")
		return Err(7)
	}
	contentBytes = userlib.SymEnc(RandKey, []byte(userdata.UUiD.String())[:16], toSave)
	userlib.DatastoreSet(f_owner, contentBytes)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	var to_return []byte

	f_editor, E := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.UUiD.String()))[:16])
	if E != nil {
		return to_return, Err(3)
	}

	info, bol := userlib.DatastoreGet(f_editor)
	if !bol {
		return to_return, Err(8)
	}

	var f_owner uuid.UUID
	var RandKey []byte
	var BlockiD uuid.UUID
	var symKey []byte

	fpdata, E := userlib.PKEDec(userdata.privateKey, info)
	if E != nil {
		return to_return, Err(3)
	}
	var filepointer FilePointer
	E = json.Unmarshal(fpdata, &filepointer)
	if E != nil {
		return to_return, Err(3)
	}

	f_owner = filepointer.F_owner
	RandKey = filepointer.RandKey

	info, bol = userlib.DatastoreGet(f_owner)
	if !bol {
		return to_return, Err(3)
	}

	if len(RandKey) != 16 || len(info) < 16 {
		fmt.Println("L1")
		return to_return, Err(7)
	}
	bpdata := userlib.SymDec(RandKey, info)
	var blockpointer BlockPointer
	E = json.Unmarshal(bpdata, &blockpointer)
	if E != nil {
		return to_return, Err(3)
	}

	symKey = blockpointer.SymKey
	BlockiD = blockpointer.BlockiD

	var cSum []byte

	for BlockiD != f_owner {
		info, bol = userlib.DatastoreGet(BlockiD)
		if !bol {
			return to_return, Err(3)
		}
		if len([]byte(f_owner.String())) < 16 || len(info) < 16 {
			fmt.Println("L2")
			return to_return, Err(7)
		}
		Tupl := userlib.SymDec([]byte(f_owner.String())[:16], info)
		var sigFile SignedFile
		E = json.Unmarshal(Tupl, &sigFile)
		if E != nil {
			return to_return, Err(3)
		}
		filedata := sigFile.FileData
		var file File
		E = json.Unmarshal(filedata, &file)
		if E != nil {
			return to_return, Err(6)
		}
		signature := sigFile.Signature
		vKey, bol := userlib.KeystoreGet("vk" + file.Creator.String())
		if !bol {
			return to_return, Err(3)
		}
		E = userlib.DSVerify(vKey, filedata, signature)
		if E != nil {
			return to_return, Err(6)
		}

		if len(symKey) != 16 || len(file.Content) < 16 {
			fmt.Println("L3")
			return to_return, Err(7)
		}
		toAdd := userlib.SymDec(symKey, file.Content)
		toAdd = reverseBytes(toAdd)
		cSum = append(cSum, toAdd...)

		BlockiD = file.PrevBlock
	}

	to_return = reverseBytes(cSum)

	return to_return, nil
}

// helper functions --

/*
*

Convert filename to f_editor/f_owner
@filename is the original user provided name
@id is the requesting user's UUID
@return filename in type string

*
*/
func ConvertFilename(filename string, id uuid.UUID) (f uuid.UUID) {
	f_editor, E := uuid.FromBytes(userlib.Hash([]byte(filename + id.String()))[:16])
	if E != nil {
		return uuid.Nil
	}
	return f_editor

}

/*
*

Convert username to uuid in type string
@username in type string
@return uuid (UUID)

*
*/
func ConvertUsername(username string) (u uuid.UUID) {
	user_n, E := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if E != nil {
		return uuid.Nil
	}
	return user_n
}

/*
*

/**

Error checking for CreateInvitation
@filename of file to be shared
@recipientUsername string version of recipient name
@error, else nil

*
*/
func ErrorCheckInvites(filename string, recipientUsername string) error {
	_, UsernameError := userlib.DatastoreGet(ConvertUsername(recipientUsername))
	_, FileError := userlib.DatastoreGet(ConvertFilename(filename, ConvertUsername(recipientUsername)))

	if UsernameError {
		return Err(4)
	} else if FileError {
		return Err(8)
	} else {
		return nil
	}

}

/*
*

Error checking for AcceptInvitation
@filename of editor's selected new filename
@recipientUsername string version of recipient name
@senderUsername string version of sender's name
@error, else nil

*
*/
func ErrorCheckAccept(filename string, recipientUsername string, senderUsername string, invitationPtr uuid.UUID) error {
	_, UUIDError := userlib.DatastoreGet(invitationPtr)
	_, FileRepeatError := userlib.DatastoreGet(ConvertFilename(filename, ConvertUsername(recipientUsername)))

	if UUIDError {
		return Err(6)
	} else if !FileRepeatError {
		return Err(2)
	} else {
		return nil
	}

	/**
	_, RevokeError := DatastoreGet(userlib.DatastoreGet(recipientUsername) + RL + randomKey)
	else if RevokeError {
		return E(6)
	}
	**/

	// TODO check for tampering and finish revoke check
}

// TODO signature helper function

/*
*

Create Invitation
@filename the recipient can gain access to
@recipientUsername the username of the person receiving the share
@return pointer to an invitation containing a struct of all critical elements

*
*/
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	inviteUUID := uuid.New()
	if ErrorCheckInvites(filename, recipientUsername) != nil {
		return uuid.Nil, ErrorCheckInvites(filename, recipientUsername)
	} else {
		var invitation Invitation
		var user User
		var file FilePointer

		ptr, _ := json.Marshal(invitation)
		userlib.DatastoreSet(inviteUUID, ptr)

		invitation.F_owner = ConvertFilename(filename, user.UUiD)
		invitation.RandKey = file.RandKey

		return inviteUUID, nil
	}
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	var user User
	if ErrorCheckAccept(filename, user.Username, senderUsername, invitationPtr) != nil {
		return ErrorCheckAccept(filename, user.Username, senderUsername, invitationPtr)
	} else {
		// add to access list
		// ConvertFilename(filename, user.Username)
	}
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
