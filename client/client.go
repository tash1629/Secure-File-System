package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// contains information about the head/root file
type FileMetadata struct { // owner encrypts
	Head                 userlib.UUID //points to original file
	HeadEncKey           []byte
	Tail                 userlib.UUID // tail contains information about the last appended block (file struct)
	TailEncKey           []byte       // if nothinh has been appended yet, tail = head
	SharedMetadataUUID   userlib.UUID
	SharedMetadataEncKey []byte
	FileOwner            string // username of file owner
}

type File struct { //each appended/new block has its own file struct
	NextAppendedFileStruct       userlib.UUID
	NextAppendedFileStructEncKey []byte
	FileContentUUID              userlib.UUID
	FileContentKey               []byte // NEW STUFF, CHANGE IN STORE FILE, APPEND FILE

}

type InvitationMetadata struct { //encrypted using a symkey involving sender+recipient
	FileMetadataUUID   userlib.UUID
	FileMetadataEncKey []byte // fileMetadataEncKey
}

type Invitation struct { // encrypted using invitee's key // stored against fileAccessUUID in acceptInvitation
	InvitationInfo    userlib.UUID // ptr to InvitationMetadata
	InvitationInfoKey []byte       // key to decrypt invitationMetadata struct
}

type SharedMetadata struct { // encKey derived from owner's rootKey
	SharedUsernames                   map[string][]string  // {immediate sharees of owner: {sharees of immediate sharee}}
	SharedUsernameToInvMetadataUUID   map[string]uuid.UUID // {sharedUsername: invitationMetatdata, ...}
	SharedUsernameToInvMetadataEncKey map[string][]byte    // {username: filename}
}

type UUIDByteArr struct { // helps w unmarshalling
	SomeUUID      userlib.UUID
	SomeByteArray []byte
}

type FileMetadataByteArr struct {
	SomeFileMetadata FileMetadata
	SomeByteArray    []byte
}

type UUIDString struct {
	SomeUUID   uuid.UUID
	SomeString string
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).

type User struct {
	Username    string
	UserSignKey userlib.DSSignKey
	UserDecKey  userlib.PKEDecKey
	RootKey     []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	/***error cases
	if a user with the same username exists
	empty username
	*check if keystore contains the input username as key
	*/
	// error case 1: empty username
	if username == "" {
		return nil, errors.New("empty username")
	}
	//error case 2: username already exists; not unique
	key, ok := userlib.KeystoreGet(username + " encKey")
	if ok { // if ok==true, username exists in the Datastore
		return nil, errors.New("username already exists")
	}
	_ = key
	//var userdata User
	//userdata.Username = username

	// create userUUID for user
	usernameBytes, err := json.Marshal(username)
	if err != nil {
		return nil, errors.New("error marshalling username")
	}
	userUUID, err := uuid.FromBytes(userlib.Hash(usernameBytes)[:16])
	if err != nil {
		return nil, errors.New("error generating userUUID")
	}

	// create rootKey for each user
	passwordBytes, err := json.Marshal(password) // should be atleast 40 bytes to provide high entropy
	if err != nil {
		return nil, errors.New("error marshalling password")
	}
	//OH QUESTION: do short passwords (less than 40 bits) give high entropy?
	hashPasswordBytes := userlib.Hash(passwordBytes) // gives 64 bytes
	//IF ERROR, TRY NOT HASHING PASSWORD
	//saltBytes := json.Marshal(username+len(username))
	saltBytes, err := json.Marshal(username)
	if err != nil {
		return nil, errors.New("salt=username could not be marshalled")
	}
	rootKey := userlib.Argon2Key(hashPasswordBytes, saltBytes, 16)

	// create public key and sign for user
	encKey, decKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("error generating encryption keys")
	}
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("error generating sign keys")
	}

	// store public keys (encryption and verify keys) in keystore
	errorBool1 := userlib.KeystoreSet(username+" encKey", encKey)
	if errorBool1 != nil {
		return nil, errors.New("error setting keystore enc key")
	}
	errorBool2 := userlib.KeystoreSet(username+" verifyKey", verifyKey)
	if errorBool2 != nil {
		return nil, errors.New("error setting keystore verify key")
	}

	//filesOwned := make(map[string]userlib.UUID)
	//filesAccKeyArr := make(map[string][]byte)
	//filesAccUUIDArr := make(map[string]userlib.UUID)

	userdata := User{
		Username:    username,
		UserSignKey: signKey,
		UserDecKey:  decKey,
		RootKey:     rootKey,
	}

	// generate key to encrypt user struct
	usernameBytes, err = json.Marshal(username)
	if err != nil {
		return nil, errors.New("error marshalling username")
	}
	firstHalfPurposeBytes, err := json.Marshal("user struct encryption ")
	if err != nil {
		return nil, errors.New("error marshalling firstHalfPurposeBytes")
	}
	purposeBytes := append(firstHalfPurposeBytes, usernameBytes...)

	userEncryptKey, err := userlib.HashKDF(rootKey, purposeBytes)
	if err != nil {
		return nil, errors.New("error generating userEncryptKey")
	}
	userEncryptKey = userEncryptKey[:16] // must truncate since userlib.SymEnc function requires 16 byte key

	// store user struct against userUUID
	userdataBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, errors.New("error marshalling userdata")
	}

	// encrypt and mac user struct
	marshalledEncUserdataAndMAC, err := EncAndMAC(userEncryptKey, userdataBytes)
	if err != nil {
		return nil, err
	}

	//create ptr to user struct
	ptrUserData := &userdata

	// store ptr to encrypted user struct against userUUID
	userlib.DatastoreSet(userUUID, marshalledEncUserdataAndMAC)

	return ptrUserData, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {

	// get user from datastore
	var user User
	// user structs are stored against userUUID
	usernameBytes, err := json.Marshal(username)
	if err != nil {
		return nil, errors.New("error marshalling username")
	}
	userUUID, err := uuid.FromBytes(userlib.Hash(usernameBytes)[:16])
	if err != nil {
		return nil, errors.New("error generating userUUID")
	}

	marshalledEncUserdataAndMAC, ok := userlib.DatastoreGet(userUUID)
	// check if user exists
	// if user doesnt exist, return error
	if !ok {
		return nil, errors.New("user doesn't exist")
	}

	//regenerate user rootKey
	passwordBytes, err := json.Marshal(password)
	if err != nil {
		return nil, errors.New("error marshalling pw")
	}
	//OH QUESTION
	hashPasswordBytes := userlib.Hash(passwordBytes) // gives 64 bytes
	saltBytes, err := json.Marshal(username)
	if err != nil {
		return nil, errors.New("salt=username could not be marshalled")
	}
	rootKey := userlib.Argon2Key(hashPasswordBytes, saltBytes, 16)

	//regenerate userEncKey (userStructEncKey)
	usernameBytes, err = json.Marshal(username)
	if err != nil {
		return nil, errors.New("error marshalling username")
	}
	firstHalfPurposeBytes, err := json.Marshal("user struct encryption ")
	if err != nil {
		return nil, errors.New("error marshalling firstHalfPurposeBytes")
	}
	purposeBytes := append(firstHalfPurposeBytes, usernameBytes...)

	userEncryptKey, err := userlib.HashKDF(rootKey, purposeBytes)
	if err != nil {
		return nil, errors.New("error generating userEncryptKey")
	}
	userEncryptKey = userEncryptKey[:16] // must truncate since userlib.SymEnc function requires 16 byte key

	var unmarshalledEncUserdataAndMAC [][]byte
	err = json.Unmarshal(marshalledEncUserdataAndMAC, &unmarshalledEncUserdataAndMAC)
	if err != nil {
		return nil, errors.New("unable to unmarshal datastore value at userUUID")
	}
	userdata, err := SymVerifyAndDecrypt(userEncryptKey, unmarshalledEncUserdataAndMAC[0], unmarshalledEncUserdataAndMAC[1])
	if err != nil {
		return nil, errors.New("userdata could not be verified and decrypted")
	}

	// if user exists
	err = json.Unmarshal(userdata, &user)
	if err != nil {
		return nil, errors.New("unable to unmarshal decrypted userdata")
	}

	return &user, nil

}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	/* Summary
	1. Owner has fileOwnedUUUD: {{FileMetadataUUID, FileMetadataEncKey}, MAC}
	   a) Owner gets fileMetadata.tail, and appends their appendedBlock File Struct to the tail's FileStruct
	2. Accessor has fileAcccessUUID : {{InvitationStructUUID, InvitationStructEncKey}, MAC}
	   a) Accessor gets headFile (fileMetadataStruct) from fileAccessUUID
	3. a) appendedBlockFileStruct.fileContentUUID is updated, and fileContent is stored against that fileContentUUID.
	   b) appendedBlockFileStructUUID = fromBytes(Hash(filename + username + " append file struct to " + tailFileStructUUID)[:16])
	   c) appendedFileContentUUID = fromBytes(Hash(filename + username + " append file content to " + tailFileStructUUID)[:16])
	**/

	// check if user is owner
	fileOwnedUUID, fileOwnedValEncKey, err := getFileOwnedUUID(filename, userdata)
	if err != nil {
		return errors.New("fileOwnedUUID could not be generated")
	}
	_ = fileOwnedValEncKey // avoids unusedVar warning

	// check if fileOwnedVal = {{FileMetadataUUID, FileMetadataEncKey}, MAC} exists in the datastore
	fileOwnedVal, fileOwnedValExist := userlib.DatastoreGet(fileOwnedUUID)
	_ = fileOwnedVal
	// get accessors fileAccessUUID
	fileAccessUUID, fileAccessValEncKey, err := getFileAccessUUID(filename, userdata)
	_ = fileAccessValEncKey
	if err != nil {
		return errors.New("fileAccessUUID could not be generated")
	}
	// get fileAccessVal = {{InvitationStructUUID, InvitationStructEncKey}, MAC}
	fileAccessVal, fileAccessValExist := userlib.DatastoreGet(fileAccessUUID)
	_ = fileAccessVal

	if !fileOwnedValExist { // not owner

		if !fileAccessValExist {
			return errors.New("user is neither owner or accessor. cannnot append")
		}

	}
	// if user is accessor/owner; get fileMetadataStruct
	var fileMetadataStruct FileMetadata
	var fileMetadataUUID uuid.UUID
	var fileMetadataEncKey []byte
	if fileAccessValExist { // user is accessor
		fileMetadataUUID, fileMetadataEncKey, err = getFileMetadataUUIDAndKeyfromFileAccessUUID(filename, userdata, fileAccessUUID)
		if err != nil {
			return errors.New("filemetadata uuid and key could not be retrieved from fileAccessUUID")
		}

		// get fileMetadata struct from fileMetadataUUID and key
		fileMetadataStruct, err = getFileMetadataFromFileMetadataUUIDAndEncKey(fileMetadataUUID, fileMetadataEncKey)
		if err != nil {
			return errors.New("fileMetadata struct could not be retrieved by accessor from fileMetatdata uuid and key")
		}
	} else if fileOwnedValExist { // user is owner
		fileMetadataUUID, fileMetadataEncKey, err = getFileMetadataUUIDAndKeyfromFileOwnedUUID(filename, userdata, fileOwnedUUID)
		if err != nil {
			return errors.New("filemetadata uuid and key could not be retrieved from fileAccessUUID")
		}

		// get fileMetadata struct from fileMetadataUUID and key
		fileMetadataStruct, err = getFileMetadataFromFileMetadataUUIDAndEncKey(fileMetadataUUID, fileMetadataEncKey)
		if err != nil {
			return errors.New("fileMetadata struct could not be retrieved by accessor from fileMetatdata uuid and key")
		}
	}

	oldFileMetadata := fileMetadataStruct
	_ = oldFileMetadata

	// access tailFileStructUUID and encKey from fileMetadataStruct
	tailFileStructUUID := fileMetadataStruct.Tail
	tailFileStructEncKey := fileMetadataStruct.TailEncKey

	// get tailFileStruct
	tailFileStruct, err := getTailFileStructFromTailUUID(filename, userdata, tailFileStructUUID, tailFileStructEncKey)
	if err != nil {
		return errors.New("cant get tail file struct from tail uuid")
	}
	_ = tailFileStruct

	// generate relavant UUID's and encKeys
	appendBlockFileStructUUID, appendBlockFileContentUUID, appendBlockFileStructEncKey, appendBlockFileContentEncKey, err := generateAppendBlockFileStructAndContentUUIDAndEncKeys(filename, userdata, tailFileStructUUID, tailFileStructEncKey)
	if err != nil {
		return errors.New("append block file struct and contentUUID and their encryption keys could not be generated")
	}
	/*Start: Append appendedBlockFileStruct to tailFileStruct*/

	// create new appendBlockFileStruct of File type
	appendBlockFileStruct := File{
		NextAppendedFileStruct:       uuid.Nil,
		NextAppendedFileStructEncKey: []byte(""), // nothing has been appended yet since file has just been created
		FileContentUUID:              appendBlockFileContentUUID,
		FileContentKey:               appendBlockFileContentEncKey,
	}

	// marshal appendBlockFileStruct
	marshalledAppFileStruct, err := json.Marshal(appendBlockFileStruct) // appendBlockFileStruct is now of []byte form
	if err != nil {
		return errors.New("append block file struct could not be marshalled")
	}

	// EncAndMac appendFSUUIDVal = {appendBlockFileStruct}
	encAppendBlockFileStruct, err := EncAndMAC(appendBlockFileStructEncKey, marshalledAppFileStruct) // gives []
	if err != nil {
		return errors.New("append block file struct could not be encrypted and MACed")
	}

	userlib.DatastoreSet(appendBlockFileStructUUID, encAppendBlockFileStruct)
	// append appendBlockFileStruct by updating tailFileStruct attributes

	tailFileStruct.NextAppendedFileStruct = appendBlockFileStructUUID
	tailFileStruct.NextAppendedFileStructEncKey = appendBlockFileStructEncKey

	// old tailFileStruct above is now prevTailFileStruct and tailFileStruct = appendBlockFileStruct
	prevTailFileStruct := tailFileStruct
	prevTailFileStructUUID := tailFileStructUUID
	prevTailFileStructEncKey := tailFileStructEncKey

	// restore prevTailFileStruct
	restoreFile(prevTailFileStruct, prevTailFileStructUUID, prevTailFileStructEncKey)

	/*End: Append appendedBlockFileStruct to tailFileStruct*/

	/*Start: Append appendFileContent to tailFileStruct*/

	// EncAndMac appendContentUUIDVal = {appendContent}
	encAppendContentVal, err := EncAndMAC(appendBlockFileContentEncKey, content)
	if err != nil {
		return errors.New("append fileContent could not be encrypted and MACed")
	}

	// store marshalledEncAppFileContent against appendFileContentUUID
	userlib.DatastoreSet(appendBlockFileContentUUID, encAppendContentVal) // prev second arg = marshalledEncAppFileContent

	/*End: Append appendFileContent to tailFileStruct*/

	// update fileMetadata
	fileMetadataStruct.Tail = appendBlockFileStructUUID
	fileMetadataStruct.TailEncKey = appendBlockFileStructEncKey

	// restore fileMetadata
	restoreFileMetadata(fileMetadataStruct, fileMetadataUUID, fileMetadataEncKey)

	return nil

}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	/*If user is owner/accessor, headFile gets overwritten with content*/
	// check if user is owner
	// get fileOwnedUUID
	fileOwnedUUID, fileOwnedEncKey, err := getFileOwnedUUID(filename, userdata)
	if err != nil {
		return errors.New("fileOwnedUUID and encKey could not be generated")
	}
	_ = fileOwnedEncKey

	// GETT encFileOwnedVal against fileOwnedUUID : {{FileMetadataUUID, FileMetadataEncKey}, MAC}
	encFileOwnedVal, fileOwnedValExist := userlib.DatastoreGet(fileOwnedUUID)
	if !fileOwnedValExist { // user is not owner; check if user is accessor

		// check if user is accessor
		// get fileAccessUUID
		fileAccessUUID, fileAccessValEncKey, err := getFileAccessUUID(filename, userdata)
		if err != nil {
			return errors.New("fileAccessUUID could not be generated")
		}
		_ = fileAccessValEncKey

		// GETT encFileAccessVal against fileAccessUUID : {{InvitationStructUUID, InvitationStructEncKey}, MAC}
		encFileAccessVal, fileAccessValExist := userlib.DatastoreGet(fileAccessUUID)
		if !fileAccessValExist {
			// user is neither the owner nor the accessor
		}
		if encFileAccessVal == nil {
			// nothing is stored against fileAccessUUID
		}

		if fileAccessValExist {
			// user is accessor not owner; accessor will overwrite content at fileContentUUID of head file
			// get fileContentUUID
			fileContentUUID, fileContentEncKey, err := getFileContentUUIDfromFileAccessUUID(filename, userdata, fileAccessUUID)
			if err != nil {
				return errors.New("fileContentUUID could not be generated")
			}

			// encrypt content
			encContent, err := EncAndMAC(fileContentEncKey, content)
			if err != nil {
				return errors.New("file content could not be encrypted and MACed")
			}

			// overwrite oldfilecontent at fileContentUUID with new encContent
			userlib.DatastoreSet(fileContentUUID, encContent)
		}

	} else { // user is owner; overwrites headfileContent
		if encFileOwnedVal == nil {
			//nothing is stored against fileOwnedUUID}
		}
		// get fileContentUUID (fileContentUUID of headFile)
		fileContentUUID, fileContentEncKey, err := getFileContentUUIDfromFileOwnedUUID(filename, userdata, fileOwnedUUID)
		if err != nil {
			return errors.New("fileContentUUID could not be generated")
		}
		// encrypt content
		encContent, err := EncAndMAC(fileContentEncKey, content)
		if err != nil {
			return errors.New("file content could not be encrypted and MACed")
		}

		// overwrite oldfilecontent at fileContentUUID with new encContent
		userlib.DatastoreSet(fileContentUUID, encContent)

	}

	/*If user is not owner/accessor, new file created and stored*/

	//Step 1 ***HANDLING FILECONTENT
	// generate new fileContentUUID and fileContentEncKey; fileContentUUID: {encFileContent, MAC} ; fileContent encrypted using fileContentEncKey
	fileContentUUID, fileContentEncKey, err := generateFileContentUUIDForHeadFile(filename, userdata)
	if err != nil {
		return errors.New("file contentUUID and key could not be generated")
	}

	//encrypt and MAC fileContent
	encFileContentAndMAC, err := EncAndMAC(fileContentEncKey, content) // content = []byte
	if err != nil {
		return errors.New("file content could not be encrypted and MACed")
	}
	//store encrypted and MAC filecontent in datastore against fileContentUUID
	userlib.DatastoreSet(fileContentUUID, encFileContentAndMAC) // encContentAndMac = []byte{fileContent, MAC}

	//Step 2 HANDLING FILE STRUCT
	//generating fileStructUUID and encKey
	fileStructUUID, fileStructEncKey, err := generateFileStructUUIDForHeadFile(filename, userdata)
	if err != nil {
		return errors.New("new file struct uuid and key could not be generated")
	}

	// initialize fileStruct
	fileStruct := File{
		NextAppendedFileStruct:       uuid.Nil,
		NextAppendedFileStructEncKey: []byte(""), // nothing has been appended yet since file has just been created
		FileContentUUID:              fileContentUUID,
		FileContentKey:               fileContentEncKey,
	}

	// marshal fileStruct
	marshalledFileStruct, err := json.Marshal(fileStruct) // FileStruct to []byte
	if err != nil {
		return errors.New("fileStruct could not be marshalled")
	}

	//encrypt and MAC fileStruct
	encFileStructAndMAC, err := EncAndMAC(fileStructEncKey, marshalledFileStruct) // [] byte to [] byte
	if err != nil {
		return errors.New("file struct could not be encrypted and MACed")
	}
	//store encrypted and MAC file struct in datastore against fileStructUUID
	userlib.DatastoreSet(fileStructUUID, encFileStructAndMAC)

	/*START Create sharedMetadata struct*/
	sharedMetadataUUID, sharedMetadataEncKey, err := generateSharedMetadataUUIDAndEncKey(filename, userdata)
	if err != nil {
		return errors.New("sharedMetadataUUID and key could not be generated")
	}

	sharedMetadataStruct := SharedMetadata{
		SharedUsernames:                   make(map[string][]string),
		SharedUsernameToInvMetadataUUID:   make(map[string]userlib.UUID),
		SharedUsernameToInvMetadataEncKey: make(map[string][]byte),
	}

	// marshal sharedMetadataStruct
	marshalledSharedMetadataStruct, err := json.Marshal(sharedMetadataStruct) // []byte type
	if err != nil {
		return errors.New("sharedMetadata struct could not be marshalled")
	}

	// Store sharedMetadata Struct against sharedMetadataUUID : {encSharedMetadataStruct}
	encSharedMetadataStruct, err := EncAndMAC(sharedMetadataEncKey, marshalledSharedMetadataStruct) // SMEncAndMac = {encMessage, err}
	// encMessage = {fileMetdadataBytes, FMEncKey}
	if err != nil {
		return errors.New("file metadata could not be encrypted and MACed")
	}

	// store encrypted and MACed sharedMetadata against the sharedMetadata UUID
	userlib.DatastoreSet(sharedMetadataUUID, encSharedMetadataStruct)
	/*END Create sharedMetadata struct*/

	/*START Step 3: Create FileMetadata struct for file*/
	// generate fileMetadataUUID and fileMetadataEncKey for fileMetadata struct; fileMetadataUUID: {{fileMetadataStruct, fileMetadataEncKey}, MAC}

	fileMetadataUUID, fileMetadataEncKey, err := generateFileMetadataUUIDForHeadFile(filename, userdata)
	if err != nil {
		return errors.New("fileMetadataUUID and key could not be generated")
	}

	// Initialize FileMetadata Struct
	fileMetadata := FileMetadata{ // contains information about the head/root file
		Head:                 fileStructUUID, //points to original/head file's fileStruct
		HeadEncKey:           fileStructEncKey,
		Tail:                 fileStructUUID, // tail contains information about the last appended block
		TailEncKey:           fileStructEncKey,
		SharedMetadataUUID:   sharedMetadataUUID,
		SharedMetadataEncKey: sharedMetadataEncKey,
		FileOwner:            userdata.Username,
	}

	// marshal fileMetadata Struct
	marshalledFileMetadataStruct, err := json.Marshal(fileMetadata) // marshalledFileMetadataAndKey = []byte type
	if err != nil {
		return errors.New("fileMetadata struct could not be marshalled")
	}

	// Store FileMetadata Struct against FileMetadatUUID (FMUUID); fileMetadataUUID : {{fileMetadatStruct}, MAC}
	encFileMetadataStruct, err := EncAndMAC(fileMetadataEncKey, marshalledFileMetadataStruct) // FMEncAndMac = {encMessage, err}
	// encMessage = {fileMetdadataBytes, FMEncKey}
	if err != nil {
		return errors.New("file metadata could not be encrypted and MACed")
	}

	// store encrypted and MACed fileMetadata against the fileMetadata UUID (FMUUID)
	userlib.DatastoreSet(fileMetadataUUID, encFileMetadataStruct) // fileMetadataUUIDVal = {{FileMetadata Type}, MAC}
	/*End Step 3*/

	/*Start Step 4: Create fileOwnedUUID*/
	fileOwnedUUID, fileOwnedEncKey, err = getFileOwnedUUID(filename, userdata) // fileOwnedUUID: {{fileMetadataUUID, fileMetadataEncKey}, MAC}
	if err != nil {
		return errors.New("couldnt generate fileOwnedUUID")
	}
	// create fileOwnedValStruct and set attributes
	fileOwnedValStruct := UUIDByteArr{
		SomeUUID:      fileMetadataUUID,
		SomeByteArray: fileMetadataEncKey,
	}

	// marshal fileOwnedVal struct of UUIDByteArr type into []byte
	marshalledfileOwnedValStruct, err := json.Marshal(fileOwnedValStruct)
	if err != nil {
		return errors.New("fileOwnedVal could not be marshalled")
	}

	// EncAndMac marshalledfileOwnedValStruct; fileOwnedVal = {fileMetadataUUID, fileMetadataEncKey} using fileOwnedEncKey
	encFileOwnedValStruct, err := EncAndMAC(fileOwnedEncKey, marshalledfileOwnedValStruct)
	if err != nil {
		return errors.New("fileOwnedVal = fileMetadataUUIDAndKey could not encrypted and MACed")
	}

	// Store marshalled fileOwnedValStruct = {{fileMetadataUUID, fileMetadataEncKey}, MAC} against fileOwnedUUID
	userlib.DatastoreSet(fileOwnedUUID, encFileOwnedValStruct)

	/*End Step 4: Create fileOwnedUUID*/

	return nil
}

// get fileMetadata from fileMetadata UUID and EncKey
func getFileMetadataFromFileMetadataUUIDAndEncKey(fileMetadataUUID uuid.UUID, fileMetadataEncKey []byte) (fileMetadata FileMetadata, err error) {
	// GETTT FileMetadataStruct from FileMetadataUUID
	encFileMetadataStruct, encFileMetadataExists := userlib.DatastoreGet(fileMetadataUUID)
	if !encFileMetadataExists {
		return FileMetadata{}, errors.New("file metadata struct doesn't exist. could be deleted")
	}

	// unmarshal encFileMetadataStruct = []byte{fileMetadataStruct, MAC} to [][]byte
	var unmarshalledEncFMStruct [][]byte
	err = json.Unmarshal(encFileMetadataStruct, &unmarshalledEncFMStruct)
	if err != nil {
		return FileMetadata{}, errors.New("cannot unmarshal enc file metadata struct")
	}

	// decrypt FileMetadataStruct
	decFileMetadataStruct, err := SymVerifyAndDecrypt(fileMetadataEncKey, unmarshalledEncFMStruct[0], unmarshalledEncFMStruct[1])
	if err != nil {
		return FileMetadata{}, errors.New("cannot decrypt enc file metadata struct")
	}

	// unmarshal decFileMetadataStruct = []byte{FileMetadataStruct} to FileMetadataStruct format
	var formatFileMetadataStruct FileMetadata
	err = json.Unmarshal(decFileMetadataStruct, &formatFileMetadataStruct)
	if err != nil {
		return FileMetadata{}, errors.New("decrypted []byte FileMetadataStruct struct couldnt be unmarshalled to FileMetadata struct format")
	}
	return formatFileMetadataStruct, nil
}

// helper function: get fileMetadataUUID and fileMetadataEncKey from fileOwnedUUID
func getFileMetadataUUIDandKey(fileOwnedValExist bool, fileOwnedUUID userlib.UUID, fileOwnedValEncKey []byte, fileAccessValExist bool, fileAccessUUID userlib.UUID, fileAccessValEncKey []byte) (fileMetadataUUID uuid.UUID, fileMetadataEncKey []byte, err error) {
	// if owner
	if fileOwnedValExist {
		// GETTT fileOwnedVal; fileOwnedUUID : {{FileMetadataUUID, FileMetadataEncKey}, MAC} = {encMSG, MAC}
		fileOwnedVal, fileOwnedOk := userlib.DatastoreGet(fileOwnedUUID) // fileOwnedVal = {{FileMetadataUUID, FileMetadataEncKey}, MAC} = {encMSG, MAC}
		if !fileOwnedOk {
			return uuid.Nil, []byte(""), errors.New("fileOwnedVal = {{FileMetadataUUID, FileMetadataEncKey}, MAC} = {encMSG, MAC} doesnt exist")
		}

		// fileOwnedUUID : []byte{{FMUUID, FMEncKey}, MAC} = {encMsg, MAC}
		// unmarshalFileOwnedVal =

		// unmarshal fileOwnedVal from []byte to [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC}
		var unmarshalledEncFileOwnedVal [][]byte
		err = json.Unmarshal(fileOwnedVal, &unmarshalledEncFileOwnedVal)
		if err != nil {
			return uuid.Nil, []byte(""), errors.New("fileOwnedVal could not be unmarshalled from []byte to [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC}")
		}

		// decrypt unmarshalledFileOwnedVal
		decUnmarshalledFileOwnedVal, err := SymVerifyAndDecrypt(fileOwnedValEncKey, unmarshalledEncFileOwnedVal[0], unmarshalledEncFileOwnedVal[1])
		if err != nil {
			return uuid.Nil, []byte(""), errors.New("fileOwnedVal could not be unmarshalled from []byte to [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC}")
		}

		// unmarshal decUnmarshalledFileOwnedVal from []byte to UUIDByteArray format
		var formatFileOwnedVal UUIDByteArr
		err = json.Unmarshal(decUnmarshalledFileOwnedVal, &formatFileOwnedVal)
		if err != nil {
			return uuid.Nil, []byte(""), errors.New("decrypted fileOwnedVal could not be formatted into UUIDByteArr")
		}

		// access fileMetadataUUID and key from UUIDByteArr type formatFileOwnedVal = {FileMetadataUUID, FileMetadataEncKey}
		fileMetadataUUID = formatFileOwnedVal.SomeUUID
		fileMetadataEncKey = formatFileOwnedVal.SomeByteArray

		return fileMetadataUUID, fileMetadataEncKey, nil

	} else if fileAccessValExist {
		fileAccessVal, fileAccessOk := userlib.DatastoreGet(fileAccessUUID) // fileAccessVal = {{InvitationUUID, InvitationKey}, MAC} = {encMessage, MAC}
		if !fileAccessOk {
			return uuid.Nil, []byte(""), errors.New("fileAccessVal = {{InvitationUUID, InvitationKey}, MAC} doesnt exist")
		}

		// get InvitationStructUUID from fileAccessVal = {{InvitationStructUUID, InvitationStructKey}, MAC} = {encMSG, MAC}
		// unmarshal fileAccessVal from []byte into [][]byte{{InvitationStructUUID, InvitationStructKey}, MAC};
		var unmarshalledFileAccessVal [][]byte
		err = json.Unmarshal(fileAccessVal, &unmarshalledFileAccessVal)
		if err != nil {
			return uuid.Nil, []byte(""), errors.New("encrypted fileAccesVal could not be unmarshalled into {{encInvitationUUID, enckey}, MAC}")
		}

		decUnmarshalledFileAccessVal, err := SymVerifyAndDecrypt(fileAccessValEncKey, unmarshalledFileAccessVal[0], unmarshalledFileAccessVal[0]) // unmarshalledFileAccessVal[0] = {InvitationMetadataUUID, InvitationMetadataKey} = {encMSG}
		// decUnmarshalledFileAccessVal = [][]byte{InvitationMetadataUUID, InvitationMetadataKey}
		if err != nil {
			return uuid.Nil, []byte(""), errors.New("fileAccessVal could not be decrypted")
		}

		// unmarshal decUnmarshalledFileAccessVal = [][]byte{InvitationMetadataUUID, InvitationMetadataKey} to achieve correct format
		var formatDecFileAccessVal UUIDByteArr
		err = json.Unmarshal(decUnmarshalledFileAccessVal, &formatDecFileAccessVal)
		if err != nil {
			return uuid.Nil, []byte(""), errors.New("decFileAccessVal could not be unmarshalled into UUIDByteArray format")
		}

		// access InvitationMetadataUUID and InvitationMetadataKey
		invitationMetadataUUID := formatDecFileAccessVal.SomeUUID
		invitationMetadataEncKey := formatDecFileAccessVal.SomeByteArray

		// GETTT invitationMetadata struct from invitationMetadataUUID
		encInvitationMetadataStruct, encInvitationMetadataExists := userlib.DatastoreGet(invitationMetadataUUID)
		if !encInvitationMetadataExists {
			return uuid.Nil, []byte(""), errors.New("invitation metadata struct doesn't exist. could be deleted")
		}

		// unmarshal encInvitationMetadataStruct = []byte{InvitationMetadataStruct, MAC} to [][]byte
		var unmarshalledEncIMStruct [][]byte
		err = json.Unmarshal(encInvitationMetadataStruct, &unmarshalledEncIMStruct)
		if err != nil {
			return uuid.Nil, []byte(""), errors.New("cannot unmarshal enc invitation metadata struct")
		}

		// decrypt InvitationMetadataStruct
		decInvitationMetadataStruct, err := SymVerifyAndDecrypt(invitationMetadataEncKey, unmarshalledEncIMStruct[0], unmarshalledEncIMStruct[1])
		if err != nil {
			return uuid.Nil, []byte(""), errors.New("cannot decrypt invitation metadata struct")
		}

		// unmarshal decInvitationMetadataStruct = []byte{InvitationMetadataStruct} to InvitationMetadatStruct format
		var formatInvitationMetadataStruct InvitationMetadata
		err = json.Unmarshal(decInvitationMetadataStruct, &formatInvitationMetadataStruct)
		if err != nil {
			return uuid.Nil, []byte(""), errors.New("decrypted []byte InvitationMetadata struct couldnt be unmarshalled to InvitationMetadata format")
		}

		// access FileMetadataUUID and key of headFile that user has access to
		fileMetadataUUID = formatInvitationMetadataStruct.FileMetadataUUID
		fileMetadataEncKey = formatInvitationMetadataStruct.FileMetadataEncKey
		return fileMetadataUUID, fileMetadataEncKey, nil
	}
	return uuid.Nil, []byte(""), err
}

func restoreSharedMetadata(sharedMetadataStruct SharedMetadata, sharedMetadataUUID uuid.UUID, sharedMetadataEncKey []byte) (err error) {

	sharedMetadataStructBytes, err := json.Marshal(sharedMetadataStruct)
	if err != nil {
		return errors.New("sharedMetadataStruct couldnt be marshalled")
	}

	encSharedMetadataStructBytes, err := EncAndMAC(sharedMetadataEncKey, sharedMetadataStructBytes)
	if err != nil {
		return errors.New("sharedMetadataStruct couldnt be encrypted")
	}

	// store sharedMetadataBytes
	userlib.DatastoreSet(sharedMetadataUUID, encSharedMetadataStructBytes)
	return nil
}

func restoreFile(fileStruct File, fileStructUUID uuid.UUID, fileStructEncKey []byte) (err error) {

	fileStructBytes, err := json.Marshal(fileStruct)
	if err != nil {
		return errors.New("filemetadata couldnt be marshalled")
	}

	encFileStructBytes, err := EncAndMAC(fileStructEncKey, fileStructBytes)
	if err != nil {
		return errors.New("filemetadata couldnt be encrypted")
	}

	// store fileMetadataBytes
	userlib.DatastoreSet(fileStructUUID, encFileStructBytes)
	return nil
}

// helper function: re-store fileMetadata
func restoreFileMetadata(fileMetadata FileMetadata, fileMetadataUUID uuid.UUID, fileMetadataEncKey []byte) (err error) {
	//fileMetadataEncKeyPurpose, hash :=
	// enc fileMetadata
	// marshal fileMetadata
	fileMetadataBytes, err := json.Marshal(fileMetadata)
	if err != nil {
		return errors.New("filemetadata couldnt be marshalled")
	}

	encFileMetadataBytes, err := EncAndMAC(fileMetadataEncKey, fileMetadataBytes)
	if err != nil {
		return errors.New("filemetadata couldnt be encrypted")
	}

	// store fileMetadataBytes
	userlib.DatastoreSet(fileMetadataUUID, encFileMetadataBytes)
	return nil

}

// helper function: generate appendBlockFileStructAndContentUUID and their encKeys
func generateAppendBlockFileStructAndContentUUIDAndEncKeys(filename string, userdata *User, tailFileStructUUID uuid.UUID, tailFileStructEncKey []byte) (appendBlockFileStructUUID uuid.UUID, appendBlockContentUUID uuid.UUID, appendBlockFileStructEncKey []byte, appendBlockContentEncKey []byte, err error) {

	/*Create appendBlockFileStructUUID and appendBlockFileStructEncKey*/
	// use tailFileStructUUID to create appendBlockFileStructUUID
	purposeAppendBlockFileStructUUID := filename + userdata.Username + tailFileStructUUID.String() + " append file struct"
	purposeAppendBlockFileStructUUIDBytes, err := json.Marshal(purposeAppendBlockFileStructUUID)
	if err != nil {
		return uuid.Nil, uuid.Nil, []byte(""), []byte(""), errors.New("AppendBlockFileStructUUID purpose could not be marshalled")
	}
	hashPurposeAppendBlockFileStructUUIDBytes := userlib.Hash(purposeAppendBlockFileStructUUIDBytes)[:16] // truncate purpose since all UUID's (appendBlockUUID in this case) needs to be 16 bytes
	appendBlockFileStructUUID, err = uuid.FromBytes(hashPurposeAppendBlockFileStructUUIDBytes)

	if err != nil {
		return uuid.Nil, uuid.Nil, []byte(""), []byte(""), errors.New("appendBlockFileStructUUID could not be generated")
	}

	// generate appendBlockFileStructEncKey
	appendBlockFileStructUUIDBytes, err := json.Marshal(appendBlockFileStructUUID)
	if err != nil {
		return uuid.Nil, uuid.Nil, []byte(""), []byte(""), errors.New("appendBlockFileStructUUID could not be marshalled")
	}

	// use appendBlockFileStructUUIDBytes to create appendBlockFileStructEncKey
	appendBlockFileStructEncKey, err = userlib.HashKDF(userdata.RootKey, appendBlockFileStructUUIDBytes)

	if err != nil {
		return uuid.Nil, uuid.Nil, []byte(""), []byte(""), errors.New("appendBlockFileStructEncKey could not be generated")
	}
	appendBlockFileStructEncKey = appendBlockFileStructEncKey[:16]

	/*Create appendBlockFileContentUUID and appendBlockFileContentEncKey*/
	// use tailFileStructUUID to create appendBlockContentUUID
	purposeAppendBlockContentUUID := filename + userdata.Username + tailFileStructUUID.String() + " append file content"
	purposeAppendBlockContentUUIDBytes, err := json.Marshal(purposeAppendBlockContentUUID)
	if err != nil {
		return uuid.Nil, uuid.Nil, []byte(""), []byte(""), errors.New("AppendBlockContentUUID purpose could not be marshalled")
	}
	hashPurposeAppendContentUUIDBytes := userlib.Hash(purposeAppendBlockContentUUIDBytes)[:16] // truncate purpose since all UUID's (appendBlockContentUUID in this case) needs to be 16 bytes
	appendBlockContentUUID, err = uuid.FromBytes(hashPurposeAppendContentUUIDBytes)

	if err != nil {
		return uuid.Nil, uuid.Nil, []byte(""), []byte(""), errors.New("appendBlockContentUUID could not be generated")
	}

	// generate appendBlockContentEncKey
	appendBlockContentUUIDBytes, err := json.Marshal(appendBlockContentUUID)
	if err != nil {
		return uuid.Nil, uuid.Nil, []byte(""), []byte(""), errors.New("appendBlockFileStructUUID could not be marshalled")
	}

	// use appendBlockContentUUIDBytes to create appendBlockContentEncKey
	appendBlockContentEncKey, err = userlib.HashKDF(userdata.RootKey, appendBlockContentUUIDBytes)
	if err != nil {
		return uuid.Nil, uuid.Nil, []byte(""), []byte(""), errors.New("appendBlockContentEncKey could not be generated")
	}
	appendBlockContentEncKey = appendBlockContentEncKey[:16]

	/*return values*/
	return appendBlockFileStructUUID, appendBlockContentUUID, appendBlockFileStructEncKey, appendBlockContentEncKey, nil

}

// helper function: get FileStruct from tailFileStructUUID
func getTailFileStructFromTailUUID(filename string, userdata *User, tailFileStructUUID uuid.UUID, tailFileEncKey []byte) (fileStruct File, err error) {
	// GETTTTTT tailFile struct from tailFileUUID
	encTailFileStruct, tailFileExists := userlib.DatastoreGet(tailFileStructUUID)
	if !tailFileExists {
		return File{}, errors.New("tail file struct doesn't exist. could be deleted")
	}

	// unmarshal encTailFileStruct = []byte{tailFileStruct, MAC} to [][]byte
	var unmarshalledEncTFStruct [][]byte
	err = json.Unmarshal(encTailFileStruct, &unmarshalledEncTFStruct)
	if err != nil {
		return File{}, errors.New("couldnt unmarshal []byte{tailFileStruct, MAC} to [][]byte")
	}

	// decrypt tailFileStruct
	decTailFileStruct, err := SymVerifyAndDecrypt(tailFileEncKey, unmarshalledEncTFStruct[0], unmarshalledEncTFStruct[1])
	if err != nil {
		return File{}, errors.New("cannot decrypt invitation metadata struct")
	}

	// unmarshal decTailFileStruct = []byte{TailFileStruct} to TailFileStruct format
	var formatTailFileStruct File
	err = json.Unmarshal(decTailFileStruct, &formatTailFileStruct)
	if err != nil {
		return File{}, errors.New("decrypted []byte FileMetadataStruct struct couldnt be unmarshalled to FileMetadata struct format")
	}

	return formatTailFileStruct, nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	/*Summary lets assume we have a chain of file Structs.
	  1. Owner has fileOwnedUUUD: {{FileMetadataUUID, FileMetadataEncKey}, MAC}
	     a) Owner gets headFile from fileAccessUUID
	  2. Accessor has fileAcccessUUID : {{InvitationStructUUID, InvitationStructEncKey}, MAC}
	     a) Accessor gets headFile from fileAccessUUID
	  3. From headFileStruct, get fileContent.
	  4. While nextAppendedFileStructUUID != nil, get fileContents of each fileStruct in the chain
	  **/

	//get fileOwnedUUID
	fileOwnedUUID, fileOwnedValEncKey, err := getFileOwnedUUID(filename, userdata)
	if err != nil {
		return nil, errors.New("fileOwnedUUID and its value = {{FileMetadataUUID, FileMetadataEncKey}, MAC} encKey could not be generated")
	}
	_ = fileOwnedValEncKey

	// get fileAccessUUID: {{InvitationStructUUID, InvitationStructUUIDEncKey}, MAC}
	fileAccessUUID, fileAccessValEncKey, err := getFileAccessUUID(filename, userdata)
	if err != nil {
		return nil, errors.New("fileOwnedUUID and its value = {{FileMetadataUUID, FileMetadataEncKey}, MAC} encKey could not be generated")
	}
	_ = fileAccessValEncKey

	// check if user is owner
	// fileOwnedUUID : {{FileMetadataUUID, itsEncKey}, MAC}
	fileOwnedVal, fileOwnedValExist := userlib.DatastoreGet(fileOwnedUUID)
	_ = fileOwnedVal
	fileAccessVal, fileAccessValExist := userlib.DatastoreGet(fileAccessUUID)
	_ = fileAccessVal

	// declare neccessary variables
	var headFileStructUUID uuid.UUID
	var headFileStructEncKey []byte

	if !fileOwnedValExist {
		// not owner, check if accessor
		if !fileAccessValExist {
			return []byte(""), errors.New("user is neither owner nor accessor. cant load file")
		} else { // if accessor
			// get fileMetadata from fileAccessUUID
			fileMetadata, err := getFileMetadatafromFileAccessUUID(filename, userdata, fileAccessUUID)
			if err != nil {
				return nil, errors.New("fileMetadata could not be retrieved")
			}

			// access headFileStructUUID, its key, and same for tail from fileMetadata
			headFileStructUUID = fileMetadata.Head
			headFileStructEncKey = fileMetadata.HeadEncKey

		}

	} else { // if owner
		// get fileMetadata from fileOwnedUUID
		fileMetadata, err := getFileMetadatafromFileOwnedUUID(filename, userdata, fileOwnedUUID)
		if err != nil {
			return nil, errors.New("fileMetadata could not be retrieved")
		}

		// access headFileStructUUID, its key, and same for tail from fileMetadata
		headFileStructUUID = fileMetadata.Head
		headFileStructEncKey = fileMetadata.HeadEncKey

	}

	// get headFileStruct
	headFileStruct, err := getHeadFileStructFromHeadFileUUID(filename, userdata, headFileStructUUID, headFileStructEncKey)
	if err != nil {
		return []byte(""), errors.New("head file struct doesnt exist")
	}

	// appendedContent
	var appendedContent []byte
	// iteration variables
	currFileStruct := headFileStruct
	currFileStructUUID := headFileStructUUID
	_ = currFileStructUUID
	currFileStructKey := headFileStructEncKey
	_ = currFileStructKey

	// access fileContents of all fileStructs until nextAppendedFileStrucUUID != uuid.Nil
	for currFileStructUUID != uuid.Nil {

		// get currFileStruct
		currFileStruct, err = getFileStructFromFileStructUUID(currFileStructUUID, currFileStructKey)
		if err != nil {
			return []byte(""), errors.New("curr file struct could not be retrieved from datastore")
		}

		// get fileContent
		fileContent, err := getFileContentFromFileStructUUID(currFileStructUUID, currFileStructKey)
		if err != nil {
			return []byte(""), errors.New("file content doesnt exist")
		}

		// append fileContent to appendedContent
		appendedContent = append(appendedContent, fileContent...)

		// get nextFileStruct attributes
		currFileStructUUID = currFileStruct.NextAppendedFileStruct
		currFileStructKey = currFileStruct.NextAppendedFileStructEncKey
	}
	return appendedContent, nil
}

//helper function: getFileStructFromFileStructUUIDAndKey
func getFileStructFromFileStructUUID(fileStructUUID uuid.UUID, fileStructEncKey []byte) (fileStruct File, err error) {
	encFileStruct, encFileExists := userlib.DatastoreGet(fileStructUUID)
	if !encFileExists {
		return File{}, errors.New("file struct doesn't exist. could be deleted")
	}

	// unmarshal encFileStruct = []byte{fileStruct, MAC} to [][]byte
	var unmarshalledFileStruct [][]byte
	err = json.Unmarshal(encFileStruct, &unmarshalledFileStruct)
	if err != nil {
		return File{}, errors.New("couldnt marshal encrypted file struct from []byte to [][]byte")
	}

	// decrypt fileStruct
	decFileStruct, err := SymVerifyAndDecrypt(fileStructEncKey, unmarshalledFileStruct[0], unmarshalledFileStruct[1])
	if err != nil {
		return File{}, errors.New("couldnt decrypt encrypted file struct")
	}

	// unmarshal decFileStruct = []byte{fileStruct} to File format
	var formatFileStruct File
	err = json.Unmarshal(decFileStruct, &formatFileStruct)
	if err != nil {
		return File{}, errors.New("couldnt unmarshal file struct from []byte to File type")
	}
	return formatFileStruct, nil
}

// get file content from fileStructUUID and key
func getFileContentFromFileStructUUID(fileStructUUID uuid.UUID, fileStructEncKey []byte) (fileContent []byte, err error) {
	// GETTTTTT file struct from fileStructUUID
	encFileStruct, encFileExists := userlib.DatastoreGet(fileStructUUID)
	if !encFileExists {
		return []byte(""), errors.New("file struct doesn't exist. could be deleted")
	}

	// unmarshal encFileStruct = []byte{fileStruct, MAC} to [][]byte
	var unmarshalledFileStruct [][]byte
	err = json.Unmarshal(encFileStruct, &unmarshalledFileStruct)
	if err != nil {
		return []byte(""), errors.New("couldnt marshal encrypted file struct from []byte to [][]byte")
	}

	// decrypt fileStruct
	decFileStruct, err := SymVerifyAndDecrypt(fileStructEncKey, unmarshalledFileStruct[0], unmarshalledFileStruct[1])
	if err != nil {
		return []byte(""), errors.New("couldnt decrypt encrypted file struct")
	}

	// unmarshal decFileStruct = []byte{fileStruct} to File format
	var formatFileStruct File
	err = json.Unmarshal(decFileStruct, &formatFileStruct)
	if err != nil {
		return []byte(""), errors.New("couldnt unmarshal file struct from []byte to File type")
	}

	// get fileContentUUID from fileStruct
	fileContentUUID := formatFileStruct.FileContentUUID
	fileContentKey := formatFileStruct.FileContentKey

	// get fileContent from fileContentUUID and fileContentKey
	fileContent, err = getFileContentFromFileContentUUID(fileContentUUID, fileContentKey)
	if err != nil {
		return []byte(""), errors.New("file content doesnt exist")
	}
	return fileContent, nil

}

// helper function: getFileContentFromFileContentUUID
func getFileContentFromFileContentUUID(fileContentUUID uuid.UUID, fileContentEncKey []byte) (content []byte, err error) {
	// get encFileContent = {encFileContent, MAC}
	encFileContent, fileContentExist := userlib.DatastoreGet(fileContentUUID)
	if !fileContentExist {
		return []byte(""), errors.New("file content doesnt exist")
	}

	// unmarshal []byte encFileContent to [][]byte {encFileContent, MAC}
	var unmarshalledEncFileContent [][]byte
	err = json.Unmarshal(encFileContent, &unmarshalledEncFileContent)
	if err != nil {
		return []byte(""), errors.New("enc file content cannot be unmarshalled to [][]byte")
	}

	// decrypt fileContent
	decFileContent, err := SymVerifyAndDecrypt(fileContentEncKey, unmarshalledEncFileContent[0], unmarshalledEncFileContent[1])
	if err != nil {
		return []byte(""), errors.New("file content cannot be decrypted")
	}

	return decFileContent, nil

}

// get headFileStruct from headFileStructUUID
func getHeadFileStructFromHeadFileUUID(filename string, userdata *User, headFileStructUUID uuid.UUID, headFileStructEncKey []byte) (headFileStruct File, err error) {

	// GETTTTTT headFile struct from headFileUUID
	encHeadFileStruct, encHeadFileExists := userlib.DatastoreGet(headFileStructUUID)
	if !encHeadFileExists {
		return File{}, errors.New("head file struct doesn't exist. could be deleted")
	}

	// unmarshal encHeadFileStruct = []byte{headFileStruct, MAC} to [][]byte
	var unmarshalledEncHFStruct [][]byte
	err = json.Unmarshal(encHeadFileStruct, &unmarshalledEncHFStruct)
	if err != nil {
		return File{}, errors.New("couldnt marshal encrypted head file struct from []byte to [][]byte")
	}

	// decrypt headFileStruct
	decHeadFileStruct, err := SymVerifyAndDecrypt(headFileStructEncKey, unmarshalledEncHFStruct[0], unmarshalledEncHFStruct[1])
	if err != nil {
		return File{}, errors.New("couldnt decrypt encrypted head file struct")
	}

	// unmarshal decHeadFileStruct = []byte{HeadFileStruct} to HeadFileStruct format
	var formatHeadFileStruct File
	err = json.Unmarshal(decHeadFileStruct, &formatHeadFileStruct)
	if err != nil {
		return File{}, errors.New("couldnt unmarshal head file struct from []byte to File type")
	}
	return formatHeadFileStruct, nil
}

// helper function: generate sharedMetadata struct UUID and encKey
func generateSharedMetadataUUIDAndEncKey(filename string, userdata *User) (sharedMetadataUUID uuid.UUID, sharedMetadataEncKey []byte, err error) {
	// generate FileMetadataUUID
	sharedMetadataUUIDPurpose := filename + userdata.Username + " shared metadata UUID" // each file of an owner will have a unique sharedMetadataUUID
	sharedMetadataUUIDPurposeBytes, err := json.Marshal(sharedMetadataUUIDPurpose)
	hashSharedMetadataUUIDPurposeBytes := userlib.Hash(sharedMetadataUUIDPurposeBytes)[:16]

	if err != nil {
		return uuid.Nil, []byte(""), errors.New("purpose bytes for shared metadata UUID could not be marshalled")
	}
	sharedMetadataUUID, err = uuid.FromBytes(hashSharedMetadataUUIDPurposeBytes) // sharedmetadata UUID
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("file metadata UUID could not be generated")
	}
	// Create sharedMetadataEncKey (FMEncKey)
	sharedMetadataEncKeyPurpose := filename + userdata.Username + " shared metadata enc key"
	sharedMetadataEncKeyPurposeBytes, err := json.Marshal(sharedMetadataEncKeyPurpose)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("shared metadata encKey purpose could not be marshalled")
	}
	sharedMetadataEncKey, err = userlib.HashKDF(userdata.RootKey, sharedMetadataEncKeyPurposeBytes) // FileMetadata Enc Key
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("shared metadata encKey could not be derived")
	}
	sharedMetadataEncKey = sharedMetadataEncKey[:16]

	return sharedMetadataUUID, sharedMetadataEncKey, nil

}

// helper function: generate fileMetadataUUID and encKey for head file
func generateFileMetadataUUIDForHeadFile(filename string, userdata *User) (fileMetadataUUID uuid.UUID, fileMetadataEncKey []byte, err error) {
	// generate FileMetadataUUID
	fileMetadataUUIDPurpose := filename + userdata.Username + " file metadata UUID"
	fileMetadataUUIDPurposeBytes, err := json.Marshal(fileMetadataUUIDPurpose)
	hashFileMetadataUUIDPurposeBytes := userlib.Hash(fileMetadataUUIDPurposeBytes)[:16]

	if err != nil {
		return uuid.Nil, []byte(""), errors.New("purpose bytes for file metadata UUID could not be marshalled")
	}
	fileMetadataUUID, err = uuid.FromBytes(hashFileMetadataUUIDPurposeBytes) // Filemetadata UUID
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("file metadata UUID could not be generated")
	}

	// Create fileMetadataEncKey (FMEncKey)
	fileMetadataEncKeyPurpose := filename + userdata.Username + " file metadata enc key"
	fileMetadataEncKeyPurposeBytes, err := json.Marshal(fileMetadataEncKeyPurpose)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("file metadata encKey purpose could not be marshalled")
	}
	fileMetadataEncKey, err = userlib.HashKDF(userdata.RootKey, fileMetadataEncKeyPurposeBytes) // FileMetadata Enc Key
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("file metadata encKey could not be derived")
	}
	fileMetadataEncKey = fileMetadataEncKey[:16]
	return fileMetadataUUID, fileMetadataEncKey, nil
}

// helper function: generate file struct UUID for head file
func generateFileStructUUIDForHeadFile(filename string, userdata *User) (fileStructUUID uuid.UUID, fileStructEncKey []byte, err error) {
	//generating fileStructUUID
	fileStructUUIDPurposeBytes, err := json.Marshal(filename + userdata.Username + " file struct UUID")
	hashFileStructUUIDPurposeBytes := userlib.Hash(fileStructUUIDPurposeBytes)[:16]
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("file struct uuid purpose could not be marshalled")
	}
	fileStructUUID, err = uuid.FromBytes(hashFileStructUUIDPurposeBytes)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("file struct uuid could not be generated")
	}
	//generating fileStructEncryptionKey
	fileStructKeyPurposeBytes, err := json.Marshal(filename + userdata.Username + " file struct enc key")
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("purpose bytes for file struct key could not be marshalled")
	}

	fileStructEncKey, err = userlib.HashKDF(userdata.RootKey, fileStructKeyPurposeBytes)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("file struct enc key could not be derived")
	}
	fileStructEncKey = fileStructEncKey[:16]
	return fileStructUUID, fileStructEncKey, nil

}

// helper function: generate owner's new fileContentUUID for head file
func generateFileContentUUIDForHeadFile(filename string, userdata *User) (fileContentUUID uuid.UUID, fileContentEncKey []byte, err error) {
	//generating fileContentUUID
	fileContentUUIDPurposeBytes, err := json.Marshal(filename + userdata.Username + " file content UUID")
	hashFileContentUUIDPurposeBytes := userlib.Hash(fileContentUUIDPurposeBytes)[:16]
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("purpose bytes for file content UUID could not be marshalled")
	}
	fileContentUUID, err = uuid.FromBytes(hashFileContentUUIDPurposeBytes)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("purpose bytes for file content UUID could not be marshalled")
	}

	//generating fileContentEncryptionKey
	fileContentKeyPurposeBytes, err := json.Marshal(filename + userdata.Username + " file content enc key")
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("purpose bytes for file content key could not be marshalled")
	}
	fileContentEncKey, err = userlib.HashKDF(userdata.RootKey, fileContentKeyPurposeBytes)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("purpose bytes for file content key could not be marshalled")
	}
	fileContentEncKey = fileContentEncKey[:16]

	return fileContentUUID, fileContentEncKey, nil

}

// helper function: getFileAccessUUID; generates/gets fileAccessUUID
func getFileAccessUUID(filename string, userdata *User) (fileAccessUUID userlib.UUID, fileAccessValEncKey []byte, err error) {

	// generate fileAccessUUID
	fileAccessUUIDPurpose := filename + userdata.Username + " access"
	fileAccessUUIDPurposeBytes, err := json.Marshal(fileAccessUUIDPurpose)
	hashFileAccessUUIDPurposeBytes := userlib.Hash(fileAccessUUIDPurposeBytes)[:16]
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileAccessUUIDPurposeBytes could not be marshalled")
	}
	fileAccessUUID, err = uuid.FromBytes(hashFileAccessUUIDPurposeBytes)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("FileAccessUUID could not be generated")
	}
	fileAccessUUIDBytes, err := json.Marshal(fileAccessUUID)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("FileAccessUUID could not be marshalled")
	}
	fileAccessValEncKey, err = userlib.HashKDF(userdata.RootKey, fileAccessUUIDBytes)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileAccessValEncKey could not be generated")
	}
	fileAccessValEncKey = fileAccessValEncKey[:16]
	return fileAccessUUID, fileAccessValEncKey, nil

}

// helper function: getFileOwnedUUID; generates/gets fileOwnedUUID and fileOwnedEncKey
func getFileOwnedUUID(filename string, userdata *User) (fileOwnedUUID userlib.UUID, fileOwnedEncKey []byte, err error) {
	fileOwnedUUIDPurpose := filename + userdata.Username + " own"
	fileOwnedUUIDPurposeBytes, err := json.Marshal(fileOwnedUUIDPurpose)
	hashFileOwnedUUIDPurposeBytes := userlib.Hash(fileOwnedUUIDPurposeBytes)[:16]
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileOwnedUUIDPurposeBytes could not be marshalled")
	}
	fileOwnedUUID, err = uuid.FromBytes(hashFileOwnedUUIDPurposeBytes) // must be 16 bytes
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("FileOwnedUUID could not be generated")
	}
	// marshal fileOwnedUUID
	fileOwnedUUIDBytes, err := json.Marshal(fileOwnedUUID)
	_ = fileOwnedUUIDBytes

	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileOwnedUUID could not be marshalled")
	}
	fileOwnedEncKey, err = userlib.HashKDF(userdata.RootKey, fileOwnedUUIDPurposeBytes) // encryptes value stord against fileOwnedUUID
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileOwnedEncKey could not be generated")
	}
	fileOwnedEncKey = fileOwnedEncKey[:16]

	return fileOwnedUUID, fileOwnedEncKey, nil

}

// helper function (used in append): get fileMetatdata struct from fileAccessUUID : {{InvitationStructUUID, InvitationStructKey}, MAC} = {encMSG, MAC}
func getFileMetadatafromFileAccessUUID(filename string, userdata *User, fileAccessUUID userlib.UUID) (fileMetadataStruct FileMetadata, err error) {
	// GETTT fileAccessVal; fileAccessUUID : {{InvitationUUID, SenderName}, MAC} = {encMSG, MAC}
	// InvitationStruct is encrypted using user's publicKey
	fileAccessVal, fileAccessOk := userlib.DatastoreGet(fileAccessUUID) // fileAccessVal = {{InvitationUUID}, MAC} = {encMessage, MAC}
	if !fileAccessOk {
		return FileMetadata{}, errors.New("fileAccessVal = {{InvitationUUID, InvitationKey}, MAC} doesnt exist")
	}

	// get InvitationStructUUID from fileAccessVal = {{InvitationUUID, SenderName}, Sign} = {encMSG, MAC}
	// unmarshal fileAccessVal from []byte into [][]byte{{InvitationUUID, SenderName}, Sign} = {encMsg, MAC};
	var unmarshalledFileAccessVal [][]byte
	err = json.Unmarshal(fileAccessVal, &unmarshalledFileAccessVal)
	if err != nil {
		return FileMetadata{}, errors.New("encrypted fileAccesVal could not be unmarshalled into {{encInvitationUUID, enckey}, MAC}")
	}

	fileAccessUUIDBytes, err := json.Marshal(fileAccessUUID)
	if err != nil {
		return FileMetadata{}, errors.New("fileAccessUUID could not be marshalled")
	}
	fileAccessValEncKey, err := userlib.HashKDF(userdata.RootKey, fileAccessUUIDBytes)
	if err != nil {
		return FileMetadata{}, errors.New("enc key for fileAccessVal could not be generated")
	}
	fileAccessValEncKey = fileAccessValEncKey[:16] // decrypts fileAccessVal = {{InvitationUUID, SenderName}, Sign} stored against fileAccessUUID

	decUnmarshalledFileAccessVal, err := SymVerifyAndDecrypt(fileAccessValEncKey, unmarshalledFileAccessVal[0], unmarshalledFileAccessVal[1])
	// decUnmarshalledFileAccessVal = []byte{InvitationUUID}
	if err != nil {
		return FileMetadata{}, errors.New("fileAccessVal could not be decrypted")
	}

	// unmarshal decUnmarshalledFileAccessVal = {InvitationUUID, senderName} to achieve correct format
	var formatDecFileAccessVal UUIDString // {InvitationUUID, sender's name}
	err = json.Unmarshal(decUnmarshalledFileAccessVal, &formatDecFileAccessVal)
	if err != nil {
		return FileMetadata{}, errors.New("decFileAccessVal could not be unmarshalled into UUIDByteArray format")
	}
	invitationUUID := formatDecFileAccessVal.SomeUUID // still encrypted; needs to be decrypted
	sendersUsername := formatDecFileAccessVal.SomeString

	// GETTT invitation struct from invitationUUID: {{InvitationStruct}, Sign}
	encInvitationStruct, encInvitationExists := userlib.DatastoreGet(invitationUUID)
	if !encInvitationExists {
		return FileMetadata{}, errors.New("invitation metadata struct doesn't exist. could be deleted")
	}

	// InvitationUUID: []byte{{InvitationStruct, SenderName}, Sign}
	// unmarshal encInvitationStruct = []byte{{InvitationStruct, SenderName}, Sign} to [][]byte
	var unmarshalledEncInvStruct [][]byte
	err = json.Unmarshal(encInvitationStruct, &unmarshalledEncInvStruct)
	if err != nil {
		return FileMetadata{}, errors.New("cannot unmarshal enc invitation struct")
	}

	// invitationStructKey = user's private dec key
	invitationKey := userdata.UserDecKey
	// get sender's DSVerifyKey
	DSVerifyKey, DSVerifyKeyExist := userlib.KeystoreGet(sendersUsername + " verifyKey")
	if !DSVerifyKeyExist {
		return FileMetadata{}, errors.New("cannot get dssignkey from keystore")
	}

	// decrypt invitationStruct
	decInvitationStruct, err := VerifyAndDecrypt(invitationKey, DSVerifyKey, unmarshalledEncInvStruct[0], unmarshalledEncInvStruct[1]) // unmarshalledEncInvStruct[0] = encInvitationStruct,  unmarshalledEncInvStruct[1] = sender's sign
	if err != nil {
		return FileMetadata{}, errors.New("cannot decrypt invitation struct")
	}

	// unmarshal decInvitationStruct = []byte{InvitationStruct} to InvitationStruct format
	var formatInvitationStruct Invitation
	err = json.Unmarshal(decInvitationStruct, &formatInvitationStruct)
	if err != nil {
		return FileMetadata{}, errors.New("decrypted []byte Invitation struct couldnt be unmarshalled to InvitationMetadata format")
	}

	// access Invitation MetadataUUID and key
	invitationMetadataUUID := formatInvitationStruct.InvitationInfo
	invitationMetadataKey := formatInvitationStruct.InvitationInfoKey

	// get invitationMetadata

	// GETTT invitation Metatdata struct from invitationMetadataUUID
	encInvitationMetadataStruct, encInvitationMetadataExists := userlib.DatastoreGet(invitationMetadataUUID)
	if !encInvitationMetadataExists {
		return FileMetadata{}, errors.New("invitation metadata struct doesn't exist. could be deleted")
	}

	// unmarshal InvitationMetadataUUID = []byte{InvitationMetadataStruct, MAC} to [][]byte
	var unmarshalledEncIMStruct [][]byte
	err = json.Unmarshal(encInvitationMetadataStruct, &unmarshalledEncIMStruct)
	if err != nil {
		return FileMetadata{}, errors.New("cannot unmarshal enc invitation metadata struct")
	}

	// decrypt invitationMetadataStruct
	decInvitationMetadataStruct, err := SymVerifyAndDecrypt(invitationMetadataKey, unmarshalledEncIMStruct[0], unmarshalledEncIMStruct[1])
	if err != nil {
		return FileMetadata{}, errors.New("cannot decrypt invitation Metadata struct")
	}
	// now decInvitationStruct = {InvitationMetadataStructUUID, InvitationMetadataEncKey}
	// format decInvitationStruct = []byte{InvitationMetadataStructUUID, InvitationMetadataEncKey} to UUIDByteArr

	// unmarshal decInvitationMetadataStruct = []byte{InvitationStructMetadata} to InvitationMetadataStruct format
	var formatInvitationMetadataStruct InvitationMetadata
	err = json.Unmarshal(decInvitationMetadataStruct, &formatInvitationMetadataStruct)
	if err != nil {
		return FileMetadata{}, errors.New("decrypted []byte InvitationMetadata struct couldnt be unmarshalled to InvitationMetadata format")
	}

	// access FileMetadataUUID and FileMetatadataKey that user has access to now
	fileMetadataUUID := formatInvitationMetadataStruct.FileMetadataUUID
	fileMetadataEncKey := formatInvitationMetadataStruct.FileMetadataEncKey

	fileMetadataStruct, err = getFileMetadataFromFileMetadataUUIDAndEncKey(fileMetadataUUID, fileMetadataEncKey)
	if err != nil {
		return FileMetadata{}, errors.New("file metadata struct could not be retrived from its uuid and enc key")
	}
	return fileMetadataStruct, nil
}

// helper function (used in append): get fileMetatdata struct from fileOwnedUUID : {{fileMetadataUUID}, fileMetadataEncKey}
func getFileMetadatafromFileOwnedUUID(filename string, userdata *User, fileOwnedUUID userlib.UUID) (fileMetadataStruct FileMetadata, err error) {
	// GETTT fileOwnedVal; fileOwnedUUID : {{FileMetadataUUID, FileMetadataEncKey}, MAC} = {encMSG, MAC}
	fileOwnedVal, fileOwnedOk := userlib.DatastoreGet(fileOwnedUUID) // fileOwnedVal = {{FileMetadataUUID, FileMetadataEncKey}, MAC} = {encMSG, MAC}
	if !fileOwnedOk {
		return FileMetadata{}, errors.New("fileOwnedVal = {{FileMetadataUUID, FileMetadataEncKey}, MAC} = {encMSG, MAC} doesnt exist")
	}

	// generate fileOwnedValEncKey
	fileOwnedValEncKeyPurpose := filename + userdata.Username + " own"
	fileOwnedValEncKeyPurposeBytes, err := json.Marshal(fileOwnedValEncKeyPurpose)
	if err != nil {
		return FileMetadata{}, errors.New("fileOwnedValEncKeyPurpose could not be marshalled into bytes")
	}
	fileOwnedValEncKey, err := userlib.HashKDF(userdata.RootKey, fileOwnedValEncKeyPurposeBytes)
	if err != nil {
		return FileMetadata{}, errors.New("fileOwnedValEncKey could not be generaeted")
	}
	fileOwnedValEncKey = fileOwnedValEncKey[:16]

	// fileOwnedUUID : []byte{{FMUUID, FMEncKey}, MAC} = {encMsg, MAC}
	// unmarshalFileOwnedVal =

	// unmarshal fileOwnedVal from []byte to [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC}
	var unmarshalledEncFileOwnedVal [][]byte
	err = json.Unmarshal(fileOwnedVal, &unmarshalledEncFileOwnedVal)
	if err != nil {
		return FileMetadata{}, errors.New("fileOwnedVal could not be unmarshalled from []byte to [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC}")
	}

	// decrypt unmarshalledFileOwnedVal
	decUnmarshalledFileOwnedVal, err := SymVerifyAndDecrypt(fileOwnedValEncKey, unmarshalledEncFileOwnedVal[0], unmarshalledEncFileOwnedVal[1])
	if err != nil {
		return FileMetadata{}, errors.New("fileOwnedVal could not be unmarshalled from []byte to [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC}")
	}

	// unmarshal decUnmarshalledFileOwnedVal from []byte to UUIDByteArray format
	var formatFileOwnedVal UUIDByteArr
	err = json.Unmarshal(decUnmarshalledFileOwnedVal, &formatFileOwnedVal)
	if err != nil {
		return FileMetadata{}, errors.New("decrypted fileOwnedVal could not be formatted into UUIDByteArr")
	}

	// access fileMetadataUUID and key from UUIDByteArr type formatFileOwnedVal = {FileMetadataUUID, FileMetadataEncKey}
	fileMetadataUUID := formatFileOwnedVal.SomeUUID
	fileMetadataEncKey := formatFileOwnedVal.SomeByteArray

	// GETTT FileMetadataStruct from FileMetadataUUID
	fileMetadataStruct, err = getFileMetadataFromFileMetadataUUIDAndEncKey(fileMetadataUUID, fileMetadataEncKey)
	if err != nil {
		return FileMetadata{}, errors.New("file metadata struct could not be retrived from its uuid and enc key")
	}
	return fileMetadataStruct, nil

}

//helper function: get fileContentUUID and fileContentKey of headFile from fileAccessUUID : {{InvitationStructUUID, InvitationStructKey}, MAC} = {encMSG, MAC}
func getFileContentUUIDfromFileAccessUUID(filename string, userdata *User, fileAccessUUID userlib.UUID) (fileContentUUID userlib.UUID, fileContentKey []byte, err error) {

	// GETTT fileAccessVal; fileAccessUUID : {{InvitationStructUUID, InvitationStructKey}, MAC} = {encMSG, MAC}
	fileAccessVal, fileAccessOk := userlib.DatastoreGet(fileAccessUUID) // fileAccessVal = {{InvitationUUID, InvitationKey}, MAC} = {encMessage, MAC}
	if !fileAccessOk {
		return uuid.Nil, []byte(""), errors.New("fileAccessVal = {{InvitationUUID, InvitationKey}, MAC} doesnt exist")
	}

	// get InvitationStructUUID from fileAccessVal = {{InvitationStructUUID, InvitationStructKey}, MAC} = {encMSG, MAC}
	// unmarshal fileAccessVal from []byte into [][]byte{{InvitationStructUUID, InvitationStructKey}, MAC};
	var unmarshalledFileAccessVal [][]byte
	err = json.Unmarshal(fileAccessVal, &unmarshalledFileAccessVal)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("encrypted fileAccesVal could not be unmarshalled into {{encInvitationUUID, enckey}, MAC}")
	}

	fileAccessUUIDBytes, err := json.Marshal(fileAccessUUID)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileAccessUUID could not be marshalled")
	}
	fileAccessValEncKey, err := userlib.HashKDF(userdata.RootKey, fileAccessUUIDBytes)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("enc key for fileAccessVal could not be generated")
	}
	fileAccessValEncKey = fileAccessValEncKey[:16] // decrypts {InvitationUUID, InvitationKey}
	decUnmarshalledFileAccessVal, err := SymVerifyAndDecrypt(fileAccessValEncKey, unmarshalledFileAccessVal[0], unmarshalledFileAccessVal[1])
	// decUnmarshalledFileAccessVal = []byte{InvitationUUID}
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileAccessVal could not be decrypted")
	}

	// unmarshal decUnmarshalledFileAccessVal = {InvitationUUID, senderName} to achieve correct format
	var formatDecFileAccessVal UUIDString // {InvitationUUID, sender's name}
	err = json.Unmarshal(decUnmarshalledFileAccessVal, &formatDecFileAccessVal)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("decFileAccessVal could not be unmarshalled into UUIDByteArray format")
	}
	invitationUUID := formatDecFileAccessVal.SomeUUID // still encrypted; needs to be decrypted
	sendersUsername := formatDecFileAccessVal.SomeString

	// GETTT invitation struct from invitationUUID: {{InvitationStruct}, Sign}
	encInvitationStruct, encInvitationExists := userlib.DatastoreGet(invitationUUID)
	if !encInvitationExists {
		return uuid.Nil, []byte(""), errors.New("invitation metadata struct doesn't exist. could be deleted")
	}

	// InvitationUUID: []byte{{InvitationStruct, SenderName}, Sign}
	// unmarshal encInvitationStruct = []byte{{InvitationStruct, SenderName}, Sign} to [][]byte
	var unmarshalledEncInvStruct [][]byte
	err = json.Unmarshal(encInvitationStruct, &unmarshalledEncInvStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot unmarshal enc invitation struct")
	}

	// invitationStructKey = user's private dec key
	invitationKey := userdata.UserDecKey
	// get sender's DSVerifyKey
	DSVerifyKey, DSVerifyKeyExist := userlib.KeystoreGet(sendersUsername + " verifyKey")
	if !DSVerifyKeyExist {
		return uuid.Nil, []byte(""), errors.New("cannot get dssignkey from keystore")
	}

	// decrypt invitationStruct
	decInvitationStruct, err := VerifyAndDecrypt(invitationKey, DSVerifyKey, unmarshalledEncInvStruct[0], unmarshalledEncInvStruct[1]) // unmarshalledEncInvStruct[0] = encInvitationStruct,  unmarshalledEncInvStruct[1] = sender's sign
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot decrypt invitation struct")
	}

	// unmarshal decInvitationStruct = []byte{InvitationStruct} to InvitationStruct format
	var formatInvitationStruct Invitation
	err = json.Unmarshal(decInvitationStruct, &formatInvitationStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("decrypted []byte Invitation struct couldnt be unmarshalled to InvitationMetadata format")
	}

	// access Invitation MetadataUUID and key
	invitationMetadataUUID := formatInvitationStruct.InvitationInfo
	invitationMetadataKey := formatInvitationStruct.InvitationInfoKey

	// GETTT invitation Metatdata struct from invitationMetadataUUID
	encInvitationMetadataStruct, encInvitationMetadataExists := userlib.DatastoreGet(invitationMetadataUUID)
	if !encInvitationMetadataExists {
		return uuid.Nil, []byte(""), errors.New("invitation metadata struct doesn't exist. could be deleted")
	}

	// unmarshal InvitationMetadataUUID = []byte{InvitationMetadataStruct, MAC} to [][]byte
	var unmarshalledEncIMStruct [][]byte
	err = json.Unmarshal(encInvitationMetadataStruct, &unmarshalledEncIMStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot unmarshal enc invitation metadata struct")
	}

	// decrypt invitationMetadataStruct
	decInvitationMetadataStruct, err := SymVerifyAndDecrypt(invitationMetadataKey, unmarshalledEncIMStruct[0], unmarshalledEncIMStruct[1])
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot decrypt invitation Metadata struct")
	}
	// now decInvitationStruct = {InvitationMetadataStructUUID, InvitationMetadataEncKey}
	// format decInvitationStruct = []byte{InvitationMetadataStructUUID, InvitationMetadataEncKey} to UUIDByteArr

	// unmarshal decInvitationMetadataStruct = []byte{InvitationStructMetadata} to InvitationMetadataStruct format
	var formatInvitationMetadataStruct InvitationMetadata
	err = json.Unmarshal(decInvitationMetadataStruct, &formatInvitationMetadataStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("decrypted []byte InvitationMetadata struct couldnt be unmarshalled to InvitationMetadata format")
	}

	// access FileMetadataUUID and FileMetatadataKey that user has access to now
	fileMetadataUUID := formatInvitationMetadataStruct.FileMetadataUUID
	fileMetadataEncKey := formatInvitationMetadataStruct.FileMetadataEncKey

	// GETTT FileMetadataStruct from FileMetadataUUID
	encFileMetadataStruct, encFileMetadataExists := userlib.DatastoreGet(fileMetadataUUID)
	if !encFileMetadataExists {
		return uuid.Nil, []byte(""), errors.New("file metadata struct doesn't exist. could be deleted")
	}

	// unmarshal encFileMetadataStruct = []byte{fileMetadataStruct, MAC} to [][]byte
	var unmarshalledEncFMStruct [][]byte
	err = json.Unmarshal(encFileMetadataStruct, &unmarshalledEncFMStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot unmarshal enc file metadata struct")
	}

	// decrypt FileMetadataStruct
	decFileMetadataStruct, err := SymVerifyAndDecrypt(fileMetadataEncKey, unmarshalledEncFMStruct[0], unmarshalledEncFMStruct[1])
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot decrypt enc file metadata struct")
	}

	// unmarshal decFileMetadataStruct = []byte{FileMetadataStruct} to FileMetadataStruct format
	var formatFileMetadataStruct FileMetadata
	err = json.Unmarshal(decFileMetadataStruct, &formatFileMetadataStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("decrypted []byte FileMetadataStruct struct couldnt be unmarshalled to FileMetadata struct format")
	}

	// access headFileUUID and headFile struct key from formatFileMetadataStruct
	headFileUUID := formatFileMetadataStruct.Head
	headFileEncKey := formatFileMetadataStruct.HeadEncKey

	// GETTTTTT headFile struct from headFileUUID
	encHeadFileStruct, encHeadFileExists := userlib.DatastoreGet(headFileUUID)
	if !encHeadFileExists {
		return uuid.Nil, []byte(""), errors.New("head file struct doesn't exist. could be deleted")
	}

	// unmarshal encHeadFileStruct = []byte{headFileStruct, MAC} to [][]byte
	var unmarshalledEncHFStruct [][]byte
	err = json.Unmarshal(encHeadFileStruct, &unmarshalledEncHFStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("couldnt unmarshal []byte{headFileStruct, MAC} to [][]byte")
	}

	// decrypt headFileStruct
	decHeadFileStruct, err := SymVerifyAndDecrypt(headFileEncKey, unmarshalledEncHFStruct[0], unmarshalledEncHFStruct[1])
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot decrypt invitation metadata struct")
	}

	// unmarshal decHeadFileStruct = []byte{HeadFileStruct} to HeadFileStruct format
	var formatHeadFileStruct File
	err = json.Unmarshal(decHeadFileStruct, &formatHeadFileStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("decrypted []byte FileMetadataStruct struct couldnt be unmarshalled to FileMetadata struct format")
	}

	// access fileContentUUID from HeadFileStruct
	fileContentUUID = formatHeadFileStruct.FileContentUUID
	fileContentKey = formatHeadFileStruct.FileContentKey

	return fileContentUUID, fileContentKey, nil
}

//helper function: get fileContentUUID and fileContentKey for headFile from fileOwnedUUID : {{fileMetadataUUID}, fileMetadataEncKey}
func getFileContentUUIDfromFileOwnedUUID(filename string, userdata *User, fileOwnedUUID userlib.UUID) (fileContentUUID userlib.UUID, fileContentKey []byte, err error) {
	// GETTT fileOwnedVal; fileOwnedUUID : {{FileMetadataUUID, FileMetadataEncKey}, MAC} = {encMSG, MAC}
	fileOwnedVal, fileOwnedOk := userlib.DatastoreGet(fileOwnedUUID) // fileOwnedVal = {{FileMetadataUUID, FileMetadataEncKey}, MAC} = {encMSG, MAC}
	if !fileOwnedOk {
		return uuid.Nil, []byte(""), errors.New("fileOwnedVal = {{FileMetadataUUID, FileMetadataEncKey}, MAC} = {encMSG, MAC} doesnt exist")
	}

	// generate fileOwnedValEncKey
	fileOwnedValEncKeyPurpose := filename + userdata.Username + " own"
	fileOwnedValEncKeyPurposeBytes, err := json.Marshal(fileOwnedValEncKeyPurpose)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileOwnedValEncKeyPurpose could not be marshalled into bytes")
	}
	fileOwnedValEncKey, err := userlib.HashKDF(userdata.RootKey, fileOwnedValEncKeyPurposeBytes)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileOwnedValEncKey could not be generaeted")
	}
	fileOwnedValEncKey = fileOwnedValEncKey[:16]

	// unmarshal fileOwnedVal from []byte to [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC}
	var unmarshalledEncFileOwnedVal [][]byte
	err = json.Unmarshal(fileOwnedVal, &unmarshalledEncFileOwnedVal)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileOwnedVal could not be unmarshalled from []byte to [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC}")
	}

	// decrypt unmarshalledFileOwnedVal
	decUnmarshalledFileOwnedVal, err := SymVerifyAndDecrypt(fileOwnedValEncKey, unmarshalledEncFileOwnedVal[0], unmarshalledEncFileOwnedVal[1])
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileOwnedVal could not be unmarshalled from []byte to [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC}")
	}

	// unmarshal decUnmarshalledFileOwnedVal from [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC} to UUIDByteArray format
	var formatFileOwnedVal UUIDByteArr
	err = json.Unmarshal(decUnmarshalledFileOwnedVal, &formatFileOwnedVal)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("decrypted fileOwnedVal could not be formatted into UUIDByteArr")
	}

	// access fileMetadataUUID and key from UUIDByteArr type formatFileOwnedVal = {FileMetadataUUID, FileMetadataEncKey}
	fileMetadataUUID := formatFileOwnedVal.SomeUUID
	fileMetadataEncKey := formatFileOwnedVal.SomeByteArray

	// GETTT FileMetadataStruct from FileMetadataUUID
	encFileMetadataStruct, encFileMetadataExists := userlib.DatastoreGet(fileMetadataUUID)
	if !encFileMetadataExists {
		return uuid.Nil, []byte(""), errors.New("file metadata struct doesn't exist. could be deleted")
	}

	// unmarshal encFileMetadataStruct = []byte{fileMetadataStruct, MAC} to [][]byte
	var unmarshalledEncFMStruct [][]byte
	err = json.Unmarshal(encFileMetadataStruct, &unmarshalledEncFMStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot unmarshal enc file metadata struct")
	}

	// decrypt FileMetadataStruct
	decFileMetadataStruct, err := SymVerifyAndDecrypt(fileMetadataEncKey, unmarshalledEncFMStruct[0], unmarshalledEncFMStruct[1])
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot decrypt enc file metadata struct")
	}

	// unmarshal decFileMetadataStruct = []byte{FileMetadataStruct} to FileMetadataStruct format
	var formatFileMetadataStruct FileMetadata
	err = json.Unmarshal(decFileMetadataStruct, &formatFileMetadataStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("decrypted []byte FileMetadataStruct struct couldnt be unmarshalled to FileMetadata struct format")
	}

	// access headFileUUID and headFile struct key from formatFileMetadataStruct
	headFileUUID := formatFileMetadataStruct.Head
	headFileEncKey := formatFileMetadataStruct.HeadEncKey

	// GETTTTTT headFile struct from headFileUUID
	encHeadFileStruct, encHeadFileExists := userlib.DatastoreGet(headFileUUID)
	if !encHeadFileExists {
		return uuid.Nil, []byte(""), errors.New("head file struct doesn't exist. could be deleted")
	}

	// unmarshal encHeadFileStruct = []byte{headFileStruct, MAC} to [][]byte
	var unmarshalledEncHFStruct [][]byte
	err = json.Unmarshal(encHeadFileStruct, &unmarshalledEncHFStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("couldnt unmarshal []byte{headFileStruct, MAC} to [][]byte")
	}

	// decrypt headFileStruct
	decHeadFileStruct, err := SymVerifyAndDecrypt(headFileEncKey, unmarshalledEncHFStruct[0], unmarshalledEncHFStruct[1])
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot decrypt invitation metadata struct")
	}

	// unmarshal decHeadFileStruct = []byte{HeadFileStruct} to HeadFileStruct format
	var formatHeadFileStruct File
	err = json.Unmarshal(decHeadFileStruct, &formatHeadFileStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("decrypted []byte FileMetadataStruct struct couldnt be unmarshalled to FileMetadata struct format")
	}

	// access fileContentUUID from HeadFileStruct
	fileContentUUID = formatHeadFileStruct.FileContentUUID
	fileContentKey = formatHeadFileStruct.FileContentKey

	return fileContentUUID, fileContentKey, nil

}

//HELPER FUNCTIONS

func SymVerifyAndDecrypt(key []byte, message []byte, givenMAC []byte) (marshalledPlaintext []byte, err error) {
	// check if MAC's are equal
	// GENERATE MAC INSIDE FUNCTION
	generatedMAC, err := userlib.HMACEval(key, message)

	if err != nil {
		return nil, errors.New("error generating MAC on message")
	}
	equalMACs := userlib.HMACEqual(generatedMAC, givenMAC)
	if equalMACs == false {
		return nil, errors.New("MACs not equal")
	}

	// decrypt message
	decFileContent := userlib.SymDec(key, message) // message = encMessage
	return decFileContent, nil

}

func EncAndMAC(key []byte, message []byte) (marshalledCiphertextAndMAC []byte, err error) { // ciphertextAndMAC[0] = encMsg
	// ciphertextAndMAC[1] = MAC
	// all keys need to be 16 bytes
	iV := userlib.RandomBytes(16)
	encMessage := userlib.SymEnc(key, iV, message) // []byte
	mac, err := userlib.HMACEval(key, encMessage)  // []byte
	if err != nil {
		return nil, errors.New("error generating MACs")
	}
	marshalledCiphertextAndMAC, err = json.Marshal([][]byte{encMessage, mac})
	if err != nil {
		return nil, errors.New("error marshalling [][]byte{encMessage, mac}")
	}
	return marshalledCiphertextAndMAC, nil
}

// ADDED CREATEINVITATION
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// check if sender is trying to create invitation for themself
	if userdata.Username == recipientUsername {
		return uuid.Nil, errors.New("sender cannot create invitation for themself")
	}

	userOwns := false
	userAccesses := false
	fileOwnedUUID, _, err := getFileOwnedUUID(filename, userdata)
	if err != nil {
		return uuid.Nil, errors.New("error generating fileOwnedUUID")
	}
	_, ok := userlib.DatastoreGet(fileOwnedUUID)
	if ok {
		userOwns = true
	}
	fileAccessUUID, _, err := getFileAccessUUID(filename, userdata)
	if err != nil {
		return uuid.Nil, errors.New("error generating fileAccessUUID")
	}
	_, ok = userlib.DatastoreGet(fileAccessUUID)
	if ok {
		userAccesses = true
	}
	if !userOwns && !userAccesses {
		return uuid.Nil, errors.New("filename does not exist in namespace of caller")
	}

	var fileMetadataUUID userlib.UUID
	var fileMetadataKey []byte
	//var fileMetadata FileMetadata
	var invitationMetadata InvitationMetadata

	if userOwns {
		//fileMetadata, err = getFileMetadatafromFileOwnedUUID(filename, userdata, fileOwnedUUID)
		fileMetadataUUID, fileMetadataKey, err = getFileMetadataUUIDAndKeyfromFileOwnedUUID(filename, userdata, fileOwnedUUID)
		if err != nil {
			return uuid.Nil, errors.New("error retrieving file metadata from fileOwnedUUID")
		}
	} else if userAccesses {
		//fileMetadata, err = getFileMetadatafromFileAccessUUID(filename, userdata, fileAccessUUID)
		fileMetadataUUID, fileMetadataKey, err = getFileMetadataUUIDAndKeyfromFileAccessUUID(filename, userdata, fileAccessUUID)
		if err != nil {
			return uuid.Nil, errors.New("error retrieving file metadata from fileAccessUUID")
		}
	} else {
		return uuid.Nil, errors.New("filename does not exist in namespace of caller")
	}
	fileMetadataKey = fileMetadataKey[:16]
	invitationMetadata = InvitationMetadata{
		FileMetadataUUID:   fileMetadataUUID,
		FileMetadataEncKey: fileMetadataKey,
	}

	//***NOT SURE HOW SECURE THESE ARE
	invitationMetadataUUIDBytes, err := json.Marshal(filename + userdata.Username + recipientUsername + " invitationMetadata UUID")
	if err != nil {
		return uuid.Nil, errors.New("error generating invitationMetadataUUIDBytes")
	}
	invitationMetadataKeyBytes, err := json.Marshal(filename + userdata.Username + recipientUsername + " invitationMetadata key")
	if err != nil {
		return uuid.Nil, errors.New("error generating invitationMetadataKeyBytes")
	}
	invitationMetadataUUIDPurpose := userlib.Hash(invitationMetadataUUIDBytes)[:16]
	invitationMetadataUUID, err := uuid.FromBytes(invitationMetadataUUIDPurpose)
	if err != nil {
		return uuid.Nil, errors.New("error generating invitationMetadataUUID")
	}
	invitationMetadataKey, err := userlib.HashKDF(userdata.RootKey, invitationMetadataKeyBytes)
	if err != nil {
		return uuid.Nil, errors.New("error generating invitationMetadataKey")
	}
	invitationMetadataKey = invitationMetadataKey[:16]

	invitationMetadataBytes, err := json.Marshal(invitationMetadata)
	if err != nil {
		return uuid.Nil, errors.New("error generating invitationMetadataBytes")
	}
	encInvitationMetadataDatastoreVal, err := EncAndMAC(invitationMetadataKey, invitationMetadataBytes)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(invitationMetadataUUID, encInvitationMetadataDatastoreVal)

	invitation := Invitation{
		InvitationInfo:    invitationMetadataUUID,
		InvitationInfoKey: invitationMetadataKey,
	}

	//***NOT SURE HOW SECURE THESE ARE
	invitationUUIDBytes, err := json.Marshal(filename + userdata.Username + recipientUsername + " invitationStruct UUID")
	if err != nil {
		return uuid.Nil, errors.New("error generating invitationUUIDBytes")
	}
	invitationUUIDPurpose := userlib.Hash(invitationUUIDBytes)[:16]
	invitationUUID, err := uuid.FromBytes(invitationUUIDPurpose)
	if err != nil {
		return uuid.Nil, errors.New("error generating invitationUUID")
	}

	// marshal invitation struct
	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, errors.New("error generating invitationBytes")
	}
	invitationEncKey, ok := userlib.KeystoreGet(recipientUsername + " encKey")
	if !ok {
		return uuid.Nil, errors.New("unable to get receiver's encryption key")
	}
	invitationSignKey := userdata.UserSignKey // using senders sign key // needs to be verified by recipient by using sender's verification key
	encInvitationDatastoreVal, err := EncryptAndSign(invitationEncKey, invitationSignKey, invitationBytes)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(invitationUUID, encInvitationDatastoreVal)

	return invitationUUID, nil
}

// change
func getFileMetadataUUIDAndKeyfromFileAccessUUID(filename string, userdata *User, fileAccessUUID userlib.UUID) (fileMetadataUUID userlib.UUID, fileMetadataKey []byte, err error) {
	// GETTT fileAccessVal; fileAccessUUID : {{InvitationUUID, SenderName}, MAC} = {encMSG, MAC}
	// InvitationStruct is encrypted using user's publicKey
	fileAccessVal, fileAccessOk := userlib.DatastoreGet(fileAccessUUID) // fileAccessVal = {{InvitationUUID}, MAC} = {encMessage, MAC}
	if !fileAccessOk {
		return uuid.Nil, []byte(""), errors.New("fileAccessVal = {{InvitationUUID, InvitationKey}, MAC} doesnt exist")
	}

	// get InvitationStructUUID from fileAccessVal = {{InvitationUUID, SenderName}, Sign} = {encMSG, MAC}
	// unmarshal fileAccessVal from []byte into [][]byte{{InvitationUUID, SenderName}, Sign} = {encMsg, MAC};
	var unmarshalledFileAccessVal [][]byte
	err = json.Unmarshal(fileAccessVal, &unmarshalledFileAccessVal)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("encrypted fileAccesVal could not be unmarshalled into {{encInvitationUUID, enckey}, MAC}")
	}

	fileAccessUUIDBytes, err := json.Marshal(fileAccessUUID)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileAccessUUID could not be marshalled")
	}
	fileAccessValEncKey, err := userlib.HashKDF(userdata.RootKey, fileAccessUUIDBytes)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("enc key for fileAccessVal could not be generated")
	}
	fileAccessValEncKey = fileAccessValEncKey[:16] // decrypts fileAccessVal = {{InvitationUUID, SenderName}, Sign} stored against fileAccessUUID

	decUnmarshalledFileAccessVal, err := SymVerifyAndDecrypt(fileAccessValEncKey, unmarshalledFileAccessVal[0], unmarshalledFileAccessVal[1])
	// decUnmarshalledFileAccessVal = []byte{InvitationUUID}
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("fileAccessVal could not be decrypted")
	}

	// unmarshal decUnmarshalledFileAccessVal = {InvitationUUID, senderName} to achieve correct format
	var formatDecFileAccessVal UUIDString // {InvitationUUID, sender's name}
	err = json.Unmarshal(decUnmarshalledFileAccessVal, &formatDecFileAccessVal)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("decFileAccessVal could not be unmarshalled into UUIDByteArray format")
	}
	invitationUUID := formatDecFileAccessVal.SomeUUID // still encrypted; needs to be decrypted
	sendersUsername := formatDecFileAccessVal.SomeString

	// GETTT invitation struct from invitationUUID: {{InvitationStruct}, Sign}
	encInvitationStruct, encInvitationExists := userlib.DatastoreGet(invitationUUID)
	if !encInvitationExists {
		return uuid.Nil, []byte(""), errors.New("invitation metadata struct doesn't exist. could be deleted")
	}

	// InvitationUUID: []byte{{InvitationStruct, SenderName}, Sign}
	// unmarshal encInvitationStruct = []byte{{InvitationStruct, SenderName}, Sign} to [][]byte
	var unmarshalledEncInvStruct [][]byte
	err = json.Unmarshal(encInvitationStruct, &unmarshalledEncInvStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot unmarshal enc invitation struct")
	}

	// invitationStructKey = user's private dec key
	invitationKey := userdata.UserDecKey
	// get sender's DSVerifyKey
	DSVerifyKey, DSVerifyKeyExist := userlib.KeystoreGet(sendersUsername + " verifyKey")
	if !DSVerifyKeyExist {
		return uuid.Nil, []byte(""), errors.New("cannot get dssignkey from keystore")
	}

	// decrypt invitationStruct
	decInvitationStruct, err := VerifyAndDecrypt(invitationKey, DSVerifyKey, unmarshalledEncInvStruct[0], unmarshalledEncInvStruct[1]) // unmarshalledEncInvStruct[0] = encInvitationStruct,  unmarshalledEncInvStruct[1] = sender's sign
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot decrypt invitation struct")
	}

	// unmarshal decInvitationStruct = []byte{InvitationStruct} to InvitationStruct format
	var formatInvitationStruct Invitation
	err = json.Unmarshal(decInvitationStruct, &formatInvitationStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("decrypted []byte Invitation struct couldnt be unmarshalled to InvitationMetadata format")
	}

	// access Invitation MetadataUUID and key
	invitationMetadataUUID := formatInvitationStruct.InvitationInfo
	invitationMetadataKey := formatInvitationStruct.InvitationInfoKey

	// get invitationMetadata

	// GETTT invitation Metatdata struct from invitationMetadataUUID
	encInvitationMetadataStruct, encInvitationMetadataExists := userlib.DatastoreGet(invitationMetadataUUID)
	if !encInvitationMetadataExists {
		return uuid.Nil, []byte(""), errors.New("invitation metadata struct doesn't exist. could be deleted")
	}

	// unmarshal InvitationMetadataUUID = []byte{InvitationMetadataStruct, MAC} to [][]byte
	var unmarshalledEncIMStruct [][]byte
	err = json.Unmarshal(encInvitationMetadataStruct, &unmarshalledEncIMStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot unmarshal enc invitation metadata struct")
	}

	// decrypt invitationMetadataStruct
	decInvitationMetadataStruct, err := SymVerifyAndDecrypt(invitationMetadataKey, unmarshalledEncIMStruct[0], unmarshalledEncIMStruct[1])
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("cannot decrypt invitation Metadata struct")
	}
	// now decInvitationStruct = {InvitationMetadataStructUUID, InvitationMetadataEncKey}
	// format decInvitationStruct = []byte{InvitationMetadataStructUUID, InvitationMetadataEncKey} to UUIDByteArr

	// unmarshal decInvitationMetadataStruct = []byte{InvitationStructMetadata} to InvitationMetadataStruct format
	var formatInvitationMetadataStruct InvitationMetadata
	err = json.Unmarshal(decInvitationMetadataStruct, &formatInvitationMetadataStruct)
	if err != nil {
		return uuid.Nil, []byte(""), errors.New("decrypted []byte InvitationMetadata struct couldnt be unmarshalled to InvitationMetadata format")
	}

	// access FileMetadataUUID and FileMetatadataKey that user has access to now
	fileMetadataUUID = formatInvitationMetadataStruct.FileMetadataUUID
	fileMetadataEncKey := formatInvitationMetadataStruct.FileMetadataEncKey

	return fileMetadataUUID, fileMetadataEncKey, nil
}

// helper function: get fileMetatdataUUID from fileOwnedUUID
func getFileMetadataUUIDAndKeyfromFileOwnedUUID(filename string, userdata *User, fileOwnedUUID userlib.UUID) (fileMetadataUUID userlib.UUID, fileMetadataKey []byte, err error) {
	// GETTT fileOwnedVal; fileOwnedUUID : {{FileMetadataUUID, FileMetadataEncKey}, MAC} = {encMSG, MAC}
	fileOwnedVal, fileOwnedOk := userlib.DatastoreGet(fileOwnedUUID) // fileOwnedVal = {{FileMetadataUUID, FileMetadataEncKey}, MAC} = {encMSG, MAC}
	if !fileOwnedOk {
		return uuid.Nil, []byte{}, errors.New("fileOwnedVal = {{FileMetadataUUID, FileMetadataEncKey}, MAC} = {encMSG, MAC} doesnt exist")
	}

	// generate fileOwnedValEncKey
	fileOwnedValEncKeyPurpose := filename + userdata.Username + " own"
	fileOwnedValEncKeyPurposeBytes, err := json.Marshal(fileOwnedValEncKeyPurpose)
	if err != nil {
		return uuid.Nil, []byte{}, errors.New("fileOwnedValEncKeyPurpose could not be marshalled into bytes")
	}
	fileOwnedValEncKey, err := userlib.HashKDF(userdata.RootKey, fileOwnedValEncKeyPurposeBytes)
	if err != nil {
		return uuid.Nil, []byte{}, errors.New("fileOwnedValEncKey could not be generaeted")
	}
	fileOwnedValEncKey = fileOwnedValEncKey[:16]

	// unmarshal fileOwnedVal from []byte to [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC}
	var unmarshalledEncFileOwnedVal [][]byte
	err = json.Unmarshal(fileOwnedVal, &unmarshalledEncFileOwnedVal)
	if err != nil {
		return uuid.Nil, []byte{}, errors.New("fileOwnedVal could not be unmarshalled from []byte to [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC}")
	}

	// decrypt unmarshalledFileOwnedVal
	decUnmarshalledFileOwnedVal, err := SymVerifyAndDecrypt(fileOwnedValEncKey, unmarshalledEncFileOwnedVal[0], unmarshalledEncFileOwnedVal[1])
	if err != nil {
		return uuid.Nil, []byte{}, errors.New("fileOwnedVal could not be unmarshalled from []byte to [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC}")
	}

	// unmarshal decUnmarshalledFileOwnedVal from [][]byte{{FileMetadataUUID, FileMetadataEncKey}, MAC} to UUIDByteArray format
	var formatFileOwnedVal UUIDByteArr
	err = json.Unmarshal(decUnmarshalledFileOwnedVal, &formatFileOwnedVal)
	if err != nil {
		return uuid.Nil, []byte{}, errors.New("decrypted fileOwnedVal could not be formatted into UUIDByteArr")
	}

	// access fileMetadataUUID and key from UUIDByteArr type formatFileOwnedVal = {FileMetadataUUID, FileMetadataEncKey}
	fileMetadataUUID = formatFileOwnedVal.SomeUUID
	fileMetadataEncKey := formatFileOwnedVal.SomeByteArray
	return fileMetadataUUID, fileMetadataEncKey, nil

}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	// edge case: user shouldnt be able to accept invitation of a file that already exists in his namespace
	fileOwnedUUID, fileOwnedValEncKey, err := getFileOwnedUUID(filename, userdata)
	_ = fileOwnedValEncKey
	if err != nil {
		return errors.New("couldnt generate fileOwnedUUID")
	}
	// check if filename exists in bobs namespace
	fileOwnedUUIDVal, filenameExist := userlib.DatastoreGet(fileOwnedUUID)
	_ = fileOwnedUUIDVal
	if filenameExist {
		// cannot accept invitation since the file already exists in user's namespace
		return errors.New("cannot accept invitation. filename already exists in user's namespace")
	}

	invitation, err := getInvitationFromInvitationUUID(userdata, senderUsername, invitationPtr, filename)
	if err != nil {
		return err
	}
	invitationMetadata, err := getInvitationMetadataFromInvitation(invitation)
	if err != nil {
		return err
	}

	//update sharedUsernames to include new user
	fileMetadataDatastoreVal, ok := userlib.DatastoreGet(invitationMetadata.FileMetadataUUID) // getting fileMetadata struct
	if !ok {
		return errors.New("error retrieving fileMetadata from datastore")
	}
	var unmarshalledFileMetadataDatastoreVal [][]byte
	err = json.Unmarshal(fileMetadataDatastoreVal, &unmarshalledFileMetadataDatastoreVal)
	if err != nil {
		return errors.New("unable to unmarshal file metadata datastore value")
	}
	decryptedFileMetadata, err := SymVerifyAndDecrypt(invitationMetadata.FileMetadataEncKey, unmarshalledFileMetadataDatastoreVal[0], unmarshalledFileMetadataDatastoreVal[1])
	if err != nil {
		return errors.New("unable to decrypt file metadata datastore value")
	}

	var fileMetadata FileMetadata
	err = json.Unmarshal(decryptedFileMetadata, &fileMetadata)
	if err != nil {
		return errors.New("error unmarshalling decrypted file metadata")
	}

	// get sharedMetadataUUID from fileMetadata
	sharedMetadataUUID := fileMetadata.SharedMetadataUUID
	sharedMetadataEncKey := fileMetadata.SharedMetadataEncKey

	// get sharedMetadataStruct
	sharedMetadata, err := getSharedMetadataStructFromSharedMetadataUUID(sharedMetadataUUID, sharedMetadataEncKey)
	if err != nil {
		return errors.New("error getting shared metadata")
	}

	sharedUsernames := sharedMetadata.SharedUsernames

	if _, ok := sharedUsernames[senderUsername]; ok {
		sharedUsernames[senderUsername] = append(sharedUsernames[senderUsername], userdata.Username)
	} else if fileMetadata.FileOwner == senderUsername {
		sharedUsernames[userdata.Username] = make([]string, 0)
	}

	// get invitationMetadata encKey from invitation struct
	invitationMetadataEncKey := invitation.InvitationInfoKey

	// update sharedUsernameToInvMetadataUUID
	sharedMetadata.SharedUsernameToInvMetadataUUID[userdata.Username] = invitation.InvitationInfo

	// update usernameToInvMetadataEncKey
	sharedUsernameToInvMetadataEncKey := sharedMetadata.SharedUsernameToInvMetadataEncKey
	sharedUsernameToInvMetadataEncKey[userdata.Username] = invitationMetadataEncKey // sharee's username : user's filename

	// restore sharedMetadata to reflect SharedUsernames update
	restoreSharedMetadata(sharedMetadata, sharedMetadataUUID, sharedMetadataEncKey)

	// fileAccessUUID : {{InvitationStructUUID, InvitationEncKey}, Mac}
	fileAccessUUID, fileAccessValEncKey, err := getFileAccessUUID(filename, userdata)
	if err != nil {
		return err
	}

	fileAccessVal := UUIDString{
		SomeUUID:   invitationPtr,
		SomeString: senderUsername,
	}

	fileAccessValBytes, err := json.Marshal(fileAccessVal)
	if err != nil {
		return errors.New("unable to marshal invitation ptr")
	}

	fileAccessDatastoreVal, err := EncAndMAC(fileAccessValEncKey, fileAccessValBytes)
	if err != nil {
		return errors.New("unable to create encrypted file access datastore value")
	}

	userlib.DatastoreSet(fileAccessUUID, fileAccessDatastoreVal) // fileAccessUUID : {{InvitationStructUUID, InvitationStructEncKey}, MAC}

	return nil
}

func getSharedMetadataStructFromSharedMetadataUUID(sharedMetadataUUID uuid.UUID, sharedMetadataEncKey []byte) (sharedMetadataStruct SharedMetadata, err error) {
	encSharedMetadataStruct, sharedMetadataExist := userlib.DatastoreGet(sharedMetadataUUID)
	if !sharedMetadataExist {
		return SharedMetadata{}, errors.New("shared metadata doesnt exist")
	}

	// unmarshall encSharedMetadataStruct to [][]byte
	var unmarshaledSharedMetadata [][]byte
	err = json.Unmarshal(encSharedMetadataStruct, &unmarshaledSharedMetadata)
	if err != nil {
		return SharedMetadata{}, errors.New("shared metadata couldnt be unmarshalled")
	}

	// decrypt
	decSharedMetadataStruct, err := SymVerifyAndDecrypt(sharedMetadataEncKey, unmarshaledSharedMetadata[0], unmarshaledSharedMetadata[1])
	if err != nil {
		return SharedMetadata{}, errors.New("shared metadata couldnt be decrypted")
	}

	// unmarshal into SharedMetadata type
	var sharedMetadata SharedMetadata
	err = json.Unmarshal(decSharedMetadataStruct, &sharedMetadata)
	if err != nil {
		return SharedMetadata{}, errors.New("shared metadata couldnt be unmarshalled from []byte to SharedMetadata type")
	}

	return sharedMetadata, nil

}

func getInvitationFromInvitationUUID(recipientUserdata *User, senderUsername string, invitationPtr uuid.UUID, filename string) (invitationStruct Invitation, err error) {
	senderVerifyKey, ok := userlib.KeystoreGet(senderUsername + " verifyKey")
	if !ok {
		return Invitation{}, errors.New("unable to retrieve sender's verify key from keystore")
	}

	datastoreVal, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return Invitation{}, errors.New("unable to retrieve invitation from datastore")
	}
	var unmarshalledDatastoreVal [][]byte
	err = json.Unmarshal(datastoreVal, &unmarshalledDatastoreVal)
	if err != nil {
		return Invitation{}, errors.New("unable to unmarshal invitation datastore value")
	}

	decryptedInvitationStruct, err := VerifyAndDecrypt(recipientUserdata.UserDecKey, senderVerifyKey, unmarshalledDatastoreVal[0], unmarshalledDatastoreVal[1])
	if err != nil {
		return Invitation{}, err
	}
	var invitation Invitation
	unmarshalErr := json.Unmarshal(decryptedInvitationStruct, &invitation)
	if unmarshalErr != nil {
		return Invitation{}, errors.New("error unmarshalling decrypted invitation struct")
	}
	return invitation, nil
}

func getInvitationMetadataFromInvitation(invitation Invitation) (invitationMetadata InvitationMetadata, err error) {
	invitationMetadataUUID := invitation.InvitationInfo
	invitationMetadataKey := invitation.InvitationInfoKey

	invitationMetadataDatastoreVal, ok := userlib.DatastoreGet(invitationMetadataUUID)
	if !ok {
		return InvitationMetadata{}, errors.New("error retrieving invitation metadata datastore value")
	}

	var unmarshalledDatastoreVal [][]byte
	err = json.Unmarshal(invitationMetadataDatastoreVal, &unmarshalledDatastoreVal)
	if err != nil {
		return InvitationMetadata{}, errors.New("error unmarshalling invitation metadata datastore value")
	}
	invitationMetadataBytes, err := SymVerifyAndDecrypt(invitationMetadataKey, unmarshalledDatastoreVal[0], unmarshalledDatastoreVal[1])
	if err != nil {
		return InvitationMetadata{}, errors.New("error marshalling invitation metadata datastore")
	}
	err = json.Unmarshal(invitationMetadataBytes, &invitationMetadata)
	if err != nil {
		return InvitationMetadata{}, errors.New("error unmarshalling invitation metadata bytes")
	}
	return invitationMetadata, nil
}

func EncryptAndSign(encKey userlib.PKEEncKey, signKey userlib.DSSignKey, message []byte) (marshalledCiphertextAndSig []byte, err error) {
	ciphertext, err := userlib.PKEEnc(encKey, message)
	if err != nil {
		return nil, errors.New("encryption failed")
	}
	sig, err := userlib.DSSign(signKey, ciphertext)
	if err != nil {
		return nil, errors.New("sign failed")
	}
	marshalledCiphertextAndSig, err = json.Marshal([][]byte{ciphertext, sig})
	if err != nil {
		return nil, errors.New("unable to marshal ciphertext and sig")
	}
	return marshalledCiphertextAndSig, nil
}

func VerifyAndDecrypt(decKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey, message []byte, sig []byte) (decrypted []byte, err error) {
	err = userlib.DSVerify(verifyKey, message, sig)
	if err != nil {
		return nil, errors.New("verify failed")
	}
	decrypted, err = userlib.PKEDec(decKey, message)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	return decrypted, nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//add "revoked access from username" to create new uuids
	//filemetadata, file linked list, file contents, uuids all must be changed

	//
	fileOwnedUUID, _, err := getFileOwnedUUID(filename, userdata)
	if err != nil {
		return errors.New("error generating fileOwnedUUID")
	}
	_, ok := userlib.DatastoreGet(fileOwnedUUID)
	if !ok {
		return errors.New("user does not own this file")
	}

	fileMetadata, err := getFileMetadatafromFileOwnedUUID(filename, userdata, fileOwnedUUID)
	if err != nil {
		return errors.New("error getting file metadata from file owned uuid")
	}
	fileMetadataUUID, fileMetadataKey, err := getFileMetadataUUIDAndKeyfromFileOwnedUUID(filename, userdata, fileOwnedUUID)
	if err != nil {
		return errors.New("error getting file metadata UUID or file metadata key from file owned UUID")
	}

	sharedMetadata, err := getSharedMetadataStructFromSharedMetadataUUID(fileMetadata.SharedMetadataUUID, fileMetadata.SharedMetadataEncKey)
	if err != nil {
		return errors.New("error getting shared metadata")
	}
	if _, ok := sharedMetadata.SharedUsernames[recipientUsername]; ok {
		garbageKey := userlib.RandomBytes(16)

		/*invitationMetadataUUIDBytes, err := json.Marshal(filename + userdata.Username + recipientUsername + " invitationMetadata UUID")
		if err != nil {
			return errors.New("error generating invitationMetadataUUIDBytes")
		}
		invitationMetadataUUIDPurpose := userlib.Hash(invitationMetadataUUIDBytes)[:16]
		invitationMetadataUUID, err := uuid.FromBytes(invitationMetadataUUIDPurpose)
		if err != nil {
			return errors.New("error generating invitationMetadataUUID")
		}*/
		invitationMetadataBytes, ok := userlib.DatastoreGet(sharedMetadata.SharedUsernameToInvMetadataUUID[recipientUsername])
		if !ok {
			return errors.New("error retrieving invitationMetadata of revoked user")
		}
		garbageInvitationMetadataBytes, err := EncAndMAC(garbageKey, invitationMetadataBytes)
		if err != nil {
			return errors.New("error encrypting revoked user's IM with garbage")
		}
		userlib.DatastoreSet(sharedMetadata.SharedUsernameToInvMetadataUUID[recipientUsername], garbageInvitationMetadataBytes)

		for _, revoked := range sharedMetadata.SharedUsernames[recipientUsername] {
			garbageKey := userlib.RandomBytes(16)

			/*invitationMetadataUUIDBytes, err := json.Marshal(filename + recipientUsername + revoked + " invitationMetadata UUID")
			if err != nil {
				return errors.New("error generating invitationMetadataUUIDBytes")
			}
			invitationMetadataUUIDPurpose := userlib.Hash(invitationMetadataUUIDBytes)[:16]
			invitationMetadataUUID, err := uuid.FromBytes(invitationMetadataUUIDPurpose)
			if err != nil {
				return errors.New("error generating invitationMetadataUUID")
			}
			invitationMetadataBytes, ok := userlib.DatastoreGet(invitationMetadataUUID)
			if !ok {
				return errors.New("error retrieving invitationMetadata of revoked user")
			}
			garbageInvitationMetadataBytes, err := EncAndMAC(garbageKey, invitationMetadataBytes)
			if err != nil {
				return errors.New("error encrypting revoked user's IM with garbage")
			}
			userlib.DatastoreSet(invitationMetadataUUID, garbageInvitationMetadataBytes)*/

			invitationMetadataBytes, ok := userlib.DatastoreGet(sharedMetadata.SharedUsernameToInvMetadataUUID[revoked])
			if !ok {
				return errors.New("error retrieving invitationMetadata of revoked user")
			}
			garbageInvitationMetadataBytes, err := EncAndMAC(garbageKey, invitationMetadataBytes)
			if err != nil {
				return errors.New("error encrypting revoked user's IM with garbage")
			}
			userlib.DatastoreSet(sharedMetadata.SharedUsernameToInvMetadataUUID[revoked], garbageInvitationMetadataBytes)
			delete(sharedMetadata.SharedUsernameToInvMetadataUUID, revoked)
			delete(sharedMetadata.SharedUsernameToInvMetadataEncKey, revoked)
		}
		delete(sharedMetadata.SharedUsernames, recipientUsername)
		delete(sharedMetadata.SharedUsernameToInvMetadataUUID, recipientUsername)
		delete(sharedMetadata.SharedUsernameToInvMetadataEncKey, recipientUsername)
	} else {
		return errors.New("this user should not be revoked")
	}

	/*if revoked, ok := fileMetadata.SharedUsernames[recipientUsername]; ok {
		// generate revokedFileAccessUUID
		revokedFileAccessUUIDPurpose := filename + recipientUsername + " access"
		revokedFileAccessUUIDPurposeBytes, err := json.Marshal(revokedFileAccessUUIDPurpose)
		hashRevokedFileAccessUUIDPurposeBytes := userlib.Hash(revokedFileAccessUUIDPurposeBytes)[:16]
		if err != nil {
			return errors.New("fileAccessUUIDPurposeBytes could not be marshalled")
		}
		revokedFileAccessUUID, err := uuid.FromBytes(hashRevokedFileAccessUUIDPurposeBytes)
		if err != nil {
			return errors.New("FileAccessUUID could not be generated")
		}
		userlib.DatastoreDelete(revokedFileAccessUUID)

		for _, revokedChild := range revoked {
			// generate revokedFileAccessUUID
			revokedFileAccessUUIDPurpose := filename + revokedChild + " access"
			revokedFileAccessUUIDPurposeBytes, err := json.Marshal(revokedFileAccessUUIDPurpose)
			hashRevokedFileAccessUUIDPurposeBytes := userlib.Hash(revokedFileAccessUUIDPurposeBytes)[:16]
			if err != nil {
				return errors.New("fileAccessUUIDPurposeBytes could not be marshalled")
			}
			revokedFileAccessUUID, err := uuid.FromBytes(hashRevokedFileAccessUUIDPurposeBytes)
			if err != nil {
				return errors.New("FileAccessUUID could not be generated")
			}
			userlib.DatastoreDelete(revokedFileAccessUUID)
		}
		delete(fileMetadata.SharedUsernames, recipientUsername)
	} else {
		return errors.New("owner should not be revoking from this user")
	}*/

	revokeUserBytes, err := json.Marshal("revoked user " + recipientUsername)
	if err != nil {
		return errors.New("error generating revoked user bytes")
	}

	//generate new fileMetadataUUID and fileMetadataKey
	oldFileMetadataUUIDBytes, err := json.Marshal(fileMetadataUUID)
	if err != nil {
		return errors.New("error marshalling fileMetadataUUID")
	}
	newFileMetadataUUIDBytes := append(oldFileMetadataUUIDBytes, revokeUserBytes...)
	newFileMetadataUUIDHashedBytes := userlib.Hash(newFileMetadataUUIDBytes)[:16]
	newFileMetadataUUID, err := uuid.FromBytes(newFileMetadataUUIDHashedBytes)
	if err != nil {
		return errors.New("error generating newFileMetadataUUID")
	}
	oldFileMetadataKeyBytes, err := json.Marshal(fileMetadataKey)
	if err != nil {
		return errors.New("error marshalling fileMetadataKey")
	}
	newFileMetadataKeyBytes := append(oldFileMetadataKeyBytes, revokeUserBytes...)
	newFileMetadataKeyHashedBytes := userlib.Hash(newFileMetadataKeyBytes)[:16]
	newFileMetadataKey, err := userlib.HashKDF(fileMetadataKey, newFileMetadataKeyHashedBytes)
	newFileMetadataKey = newFileMetadataKey[:16]
	if err != nil {
		return errors.New("error generating newFileMetadataKey")
	}

	//set up for loop to change UUID and key for each file struct in linked list
	var prevFileStruct File
	var prevNewFileStructUUID uuid.UUID
	var prevNewFileStructKey []byte
	var prevNewFileContentUUID uuid.UUID
	var prevNewFileContentKey []byte
	currentFileStructUUID := fileMetadata.Head
	currentFileStructKey := fileMetadata.HeadEncKey
	tailFileStructUUID := fileMetadata.Tail

	for tailFileStructUUID != currentFileStructUUID {
		currentFileStruct, err := getFileStructFromFileStructUUID(currentFileStructUUID, currentFileStructKey)
		if err != nil {
			return errors.New("error getting file struct from file struct uuid")
		}

		//generate new fileStructUUID and fileStructKey
		oldCurrentFileStructUUIDBytes, err := json.Marshal(currentFileStructUUID)
		if err != nil {
			return errors.New("error marshalling currentFileStructUUID")
		}
		newCurrentFileStructUUIDBytes := append(oldCurrentFileStructUUIDBytes, revokeUserBytes...)
		newCurrentFileStructUUIDHashedBytes := userlib.Hash(newCurrentFileStructUUIDBytes)[:16]
		newCurrentFileStructUUID, err := uuid.FromBytes(newCurrentFileStructUUIDHashedBytes) //new filestruct uuid
		if err != nil {
			return errors.New("error getting newCurrentFileStructUUID")
		}
		oldCurrentFileStructKeyBytes, err := json.Marshal(currentFileStructKey)
		if err != nil {
			return errors.New("error marshalling currentFileStructKey")
		}
		newCurrentFileStructKeyBytes := append(oldCurrentFileStructKeyBytes, revokeUserBytes...)
		newCurrentFileStructKeyHashedBytes := userlib.Hash(newCurrentFileStructKeyBytes)[:16]
		newCurrentFileStructKey, err := userlib.HashKDF(currentFileStructKey, newCurrentFileStructKeyHashedBytes) //new filestruct key
		newCurrentFileStructKey = newCurrentFileStructKey[:16]
		if err != nil {
			return errors.New("error generating newCurrentFileStructKey")
		}

		//generate new fileContentUUID and fileContentKey
		oldCurrentFileContentUUIDBytes, err := json.Marshal(currentFileStruct.FileContentUUID)
		if err != nil {
			return errors.New("error marshalling FileContentUUID from currentFileStruct")
		}
		newCurrentFileContentUUIDBytes := append(oldCurrentFileContentUUIDBytes, revokeUserBytes...)
		newCurrentFileContentUUIDHashedBytes := userlib.Hash(newCurrentFileContentUUIDBytes)[:16]
		newCurrentFileContentUUID, err := uuid.FromBytes(newCurrentFileContentUUIDHashedBytes) //new filecontent uuid
		if err != nil {
			return errors.New("error generating newCurrentFileContentUUID")
		}
		oldCurrentFileContentKeyBytes, err := json.Marshal(currentFileStruct.FileContentKey)
		if err != nil {
			return errors.New("error marshalling fileContentKey of currentFileStruct")
		}
		newCurrentFileContentKeyBytes := append(oldCurrentFileContentKeyBytes, revokeUserBytes...)
		newCurrentFileContentKeyHashedBytes := userlib.Hash(newCurrentFileContentKeyBytes)[:16]
		newCurrentFileContentKey, err := userlib.HashKDF(currentFileStruct.FileContentKey, newCurrentFileContentKeyHashedBytes) //new filecontent uuid
		newCurrentFileContentKey = newCurrentFileContentKey[:16]
		if err != nil {
			return errors.New("error generating newCurrentFileContentKey")
		}

		//if the head is being changed, change attributes of fileMetadata to reflect change
		if currentFileStructUUID == fileMetadata.Head {
			fileMetadata.Head = newCurrentFileStructUUID
			fileMetadata.HeadEncKey = newCurrentFileStructKey
		} else { //else store previous file struct with updated nextAppended
			//store file struct encrypted with new key against new uuid
			prevFileStruct.NextAppendedFileStruct = newCurrentFileStructUUID
			prevFileStruct.NextAppendedFileStructEncKey = newCurrentFileStructKey
			prevFileStruct.FileContentUUID = prevNewFileContentUUID
			prevFileStruct.FileContentKey = prevNewFileContentKey

			prevNewFileStructBytes, err := json.Marshal(prevFileStruct)
			if err != nil {
				return errors.New("error marshalling prevFileStruct")
			}
			prevNewFileStructDatastoreVal, err := EncAndMAC(prevNewFileStructKey, prevNewFileStructBytes)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(prevNewFileStructUUID, prevNewFileStructDatastoreVal)
		}

		prevNewFileStructUUID = newCurrentFileStructUUID
		prevNewFileStructKey = newCurrentFileStructKey
		prevNewFileContentUUID = newCurrentFileContentUUID
		prevNewFileContentKey = newCurrentFileContentKey

		//move to next node in linked list
		currentFileStructUUID = currentFileStruct.NextAppendedFileStruct
		currentFileStructKey = currentFileStruct.NextAppendedFileStructEncKey
		prevFileStruct = currentFileStruct

	}

	//updating tail uuid and key happens outside for loop
	currentFileStruct, err := getFileStructFromFileStructUUID(currentFileStructUUID, currentFileStructKey)
	if err != nil {
		return err
	}

	//generate new fileStructUUID and fileStructKey
	oldCurrentFileStructUUIDBytes, err := json.Marshal(currentFileStructUUID)
	if err != nil {
		return errors.New("error marshalling currentFileStructUUID")
	}
	newCurrentFileStructUUIDBytes := append(oldCurrentFileStructUUIDBytes, revokeUserBytes...)
	newCurrentFileStructUUIDHashedBytes := userlib.Hash(newCurrentFileStructUUIDBytes)[:16]
	newCurrentFileStructUUID, err := uuid.FromBytes(newCurrentFileStructUUIDHashedBytes) //new filestruct uuid
	if err != nil {
		return errors.New("error generating newCurrentFileStructUUID")
	}
	oldCurrentFileStructKeyBytes, err := json.Marshal(currentFileStructKey)
	if err != nil {
		return errors.New("error marshalling currentFileStructKey")
	}
	newCurrentFileStructKeyBytes := append(oldCurrentFileStructKeyBytes, revokeUserBytes...)
	newCurrentFileStructKeyHashedBytes := userlib.Hash(newCurrentFileStructKeyBytes)[:16]
	newCurrentFileStructKey, err := userlib.HashKDF(currentFileStructKey, newCurrentFileStructKeyHashedBytes) //new filestruct key
	newCurrentFileStructKey = newCurrentFileStructKey[:16]
	if err != nil {
		return errors.New("error generating newCurrentFileStructKey")
	}

	//generate new fileContentUUID and fileContentKey
	oldCurrentFileContentUUIDBytes, err := json.Marshal(currentFileStruct.FileContentUUID)
	if err != nil {
		return errors.New("error marshalling fileContentUUID of currentFileStruct")
	}
	newCurrentFileContentUUIDBytes := append(oldCurrentFileContentUUIDBytes, revokeUserBytes...)
	newCurrentFileContentUUIDHashedBytes := userlib.Hash(newCurrentFileContentUUIDBytes)[:16]
	newCurrentFileContentUUID, err := uuid.FromBytes(newCurrentFileContentUUIDHashedBytes) //new filecontent uuid
	if err != nil {
		return errors.New("error generating newCurrentFileContentUUID")
	}
	oldCurrentFileContentKeyBytes, err := json.Marshal(currentFileStruct.FileContentKey)
	if err != nil {
		return errors.New("error marshalling fileContentKey of curretnFIleStruct")
	}
	newCurrentFileContentKeyBytes := append(oldCurrentFileContentKeyBytes, revokeUserBytes...)
	newCurrentFileContentKeyHashedBytes := userlib.Hash(newCurrentFileContentKeyBytes)[:16]
	newCurrentFileContentKey, err := userlib.HashKDF(currentFileStruct.FileContentKey, newCurrentFileContentKeyHashedBytes) //new filecontent uuid
	newCurrentFileContentKey = newCurrentFileContentKey[:16]
	if err != nil {
		return errors.New("error generating newCurretnFileContentKey")
	}

	oldSharedMetadataUUIDBytes, err := json.Marshal(fileMetadata.SharedMetadataUUID)
	if err != nil {
		return errors.New("error marshalling sharedMetadataUUID")
	}
	newSharedMetadataUUIDBytes := append(oldSharedMetadataUUIDBytes, revokeUserBytes...)[:16]
	newSharedMetadataUUID, err := uuid.FromBytes(newSharedMetadataUUIDBytes)
	if err != nil {
		return errors.New("error generating newSharedMetadataUUID")
	}
	oldSharedMetadataKeyBytes, err := json.Marshal(fileMetadata.SharedMetadataEncKey)
	if err != nil {
		return errors.New("error marshalling sharedMetadataKey")
	}
	newSharedMetadataKeyBytes := append(oldSharedMetadataKeyBytes, revokeUserBytes...)
	newSharedMetadataKey, err := userlib.HashKDF(fileMetadata.SharedMetadataEncKey, newSharedMetadataKeyBytes)
	if err != nil {
		return errors.New("error generating newSharedMetadataUUID")
	}

	fileMetadata.Tail = newCurrentFileStructUUID
	fileMetadata.HeadEncKey = newCurrentFileStructKey
	fileMetadata.SharedMetadataUUID = newSharedMetadataUUID
	fileMetadata.SharedMetadataEncKey = newSharedMetadataKey

	//if the head is being changed, change attributes of fileMetadata to reflect change
	if currentFileStructUUID == fileMetadata.Head {
		fileMetadata.Head = newCurrentFileStructUUID
		fileMetadata.HeadEncKey = newCurrentFileStructKey
	} else { //else store previous file struct with updated nextAppended
		//store file struct encrypted with new key against new uuid
		prevFileStruct.NextAppendedFileStruct = newCurrentFileStructUUID
		prevFileStruct.NextAppendedFileStructEncKey = newCurrentFileStructKey
		prevFileStruct.FileContentUUID = prevNewFileContentUUID
		prevFileStruct.FileContentKey = prevNewFileContentKey

		prevNewFileStructBytes, err := json.Marshal(prevFileStruct)
		if err != nil {
			return errors.New("error marshalling prevFileStruct")
		}
		prevNewFileStructDatastoreVal, err := EncAndMAC(prevNewFileStructKey, prevNewFileStructBytes)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(prevNewFileStructUUID, prevNewFileStructDatastoreVal)
	}

	// restore new filecontent
	currentFileContent, err := getFileContentFromFileContentUUID(currentFileStruct.FileContentUUID, currentFileStruct.FileContentKey)
	if err != nil {
		return err
	}
	currentNewFileContentDatastoreVal, err := EncAndMAC(newCurrentFileContentKey, currentFileContent)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(newCurrentFileContentUUID, currentNewFileContentDatastoreVal)

	//store current file struct because it is the last node in the linked list; do not need to update nextAppended attributes
	currentFileStruct.FileContentUUID = newCurrentFileContentUUID
	currentFileStruct.FileContentKey = newCurrentFileContentKey
	currentNewFileStructBytes, err := json.Marshal(currentFileStruct)
	if err != nil {
		return errors.New("error marshalling currentFileStruct")
	}
	currentNewFileStructDatastoreVal, err := EncAndMAC(newCurrentFileStructKey, currentNewFileStructBytes)
	if err != nil {
		return err
	}

	// restore new file struct
	userlib.DatastoreSet(newCurrentFileStructUUID, currentNewFileStructDatastoreVal)

	//update IM information for unrevoked users to point to new fileMetadata

	for directChild, sharees := range sharedMetadata.SharedUsernames {

		/*invitationMetadataUUIDBytes, err := json.Marshal(filename + userdata.Username + directChild + " invitationMetadata UUID")
		if err != nil {
			return errors.New("error generating invitationMetadataUUIDBytes")
		}
		invitationMetadataKeyBytes, err := json.Marshal(filename + userdata.Username + directChild + " invitationMetadata key")
		if err != nil {
			return errors.New("error generating invitationMetadataKeyBytes")
		}
		invitationMetadataUUIDPurpose := userlib.Hash(invitationMetadataUUIDBytes)[:16]
		invitationMetadataUUID, err := uuid.FromBytes(invitationMetadataUUIDPurpose)
		if err != nil {
			return errors.New("error generating invitationMetadataUUID")
		}
		invitationMetadataKey, err := userlib.HashKDF(userdata.RootKey, invitationMetadataKeyBytes)
		if err != nil {
			return errors.New("error generating invitationMetadataKey")
		}
		invitationMetadataKey = invitationMetadataKey[:16]*/
		invitationMetadataDatastoreVal, ok := userlib.DatastoreGet(sharedMetadata.SharedUsernameToInvMetadataUUID[directChild])
		if !ok {
			return errors.New("error retrieving invitation metadata for " + directChild)
		}
		var unmarshalledDatastoreVal [][]byte
		err = json.Unmarshal(invitationMetadataDatastoreVal, &unmarshalledDatastoreVal)
		if err != nil {
			return errors.New("error unmarshalling invitation metadata datastore value")
		}
		invitationMetadataBytes, err := SymVerifyAndDecrypt(sharedMetadata.SharedUsernameToInvMetadataEncKey[directChild], unmarshalledDatastoreVal[0], unmarshalledDatastoreVal[1])
		if err != nil {
			return errors.New("error marshalling invitation metadata datastore")
		}
		var invitationMetadata InvitationMetadata
		err = json.Unmarshal(invitationMetadataBytes, &invitationMetadata)
		if err != nil {
			return errors.New("error unmarshalling invitation metadata bytes")
		}
		invitationMetadata.FileMetadataEncKey = newFileMetadataKey
		invitationMetadata.FileMetadataUUID = newFileMetadataUUID

		invitationMetadataBytes, err = json.Marshal(invitationMetadata)
		if err != nil {
			return errors.New("unable to marshal updated invitationMetadata")
		}
		invitationMetadataDatastoreVal, err = EncAndMAC(sharedMetadata.SharedUsernameToInvMetadataEncKey[directChild], invitationMetadataBytes)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(sharedMetadata.SharedUsernameToInvMetadataUUID[directChild], invitationMetadataDatastoreVal)

		for _, sharee := range sharees {
			/*invitationMetadataUUIDBytes, err := json.Marshal(filename + directChild + sharee + " invitationMetadata UUID")
			if err != nil {
				return errors.New("error generating invitationMetadataUUIDBytes")
			}
			invitationMetadataKeyBytes, err := json.Marshal(filename + directChild + sharee + " invitationMetadata key")
			if err != nil {
				return errors.New("error generating invitationMetadataKeyBytes")
			}
			invitationMetadataUUIDPurpose := userlib.Hash(invitationMetadataUUIDBytes)[:16]
			invitationMetadataUUID, err := uuid.FromBytes(invitationMetadataUUIDPurpose)
			if err != nil {
				return errors.New("error generating invitationMetadataUUID")
			}*/
			/*invitationMetadataKey, err := userlib.HashKDF(userdata.RootKey, invitationMetadataKeyBytes)
			if err != nil {
				return errors.New("error generating invitationMetadataKey")
			}
			invitationMetadataKey = invitationMetadataKey[:16]*/
			invitationMetadataDatastoreVal, ok := userlib.DatastoreGet(sharedMetadata.SharedUsernameToInvMetadataUUID[sharee])
			if !ok {
				return errors.New("error retrieving invitation metadata for " + sharee)
			}
			var unmarshalledDatastoreVal [][]byte
			err = json.Unmarshal(invitationMetadataDatastoreVal, &unmarshalledDatastoreVal)
			if err != nil {
				return errors.New("error unmarshalling invitation metadata datastore value")
			}
			invitationMetadataBytes, err := SymVerifyAndDecrypt(sharedMetadata.SharedUsernameToInvMetadataEncKey[sharee], unmarshalledDatastoreVal[0], unmarshalledDatastoreVal[1])
			if err != nil {
				return errors.New("error marshalling invitation metadata datastore")
			}
			var invitationMetadata InvitationMetadata
			err = json.Unmarshal(invitationMetadataBytes, &invitationMetadata)
			if err != nil {
				return errors.New("error unmarshalling invitation metadata bytes")
			}
			invitationMetadata.FileMetadataEncKey = newFileMetadataKey
			invitationMetadata.FileMetadataUUID = newFileMetadataUUID

			invitationMetadataBytes, err = json.Marshal(invitationMetadata)
			if err != nil {
				return errors.New("unable to marshal updated invitationMetadata")
			}
			invitationMetadataDatastoreVal, err = EncAndMAC(sharedMetadata.SharedUsernameToInvMetadataEncKey[sharee], invitationMetadataBytes)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(sharedMetadata.SharedUsernameToInvMetadataUUID[sharee], invitationMetadataDatastoreVal)
		}
	}

	//store fileMetadata encrypted with new key against new uuid
	newFileMetadataBytes, err := json.Marshal(fileMetadata)
	if err != nil {
		return errors.New("error generating new file metadata bytes")
	}
	newFileMetadataDatastoreVal, err := EncAndMAC(newFileMetadataKey, newFileMetadataBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(newFileMetadataUUID, newFileMetadataDatastoreVal)
	// DELETE STUFF

	return nil

}
