package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.

	"encoding/hex"
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const bobPassword = "iloveCS161!"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const contentFour = "I hate cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	_ = bob
	//var Bob *client.User
	var alice2 *client.User
	_ = alice2
	var charles *client.User
	_ = charles
	var doris *client.User
	_ = doris
	var eve *client.User
	_ = eve
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	_ = alicePhone
	var aliceLaptop *client.User
	var aliceDesktop *client.User
	_ = aliceDesktop
	var bobLaptop *client.User
	_ = bobLaptop
	//var BobLaptop *client.User
	var bobPhone *client.User
	_ = bobPhone
	var charlesLaptop *client.User
	_ = charlesLaptop
	var charlesPhone *client.User
	_ = charlesPhone

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	_ = charlesFile
	dorisFile := "dorisFile.txt"
	_ = dorisFile
	eveFile := "eveFile.txt"
	_ = eveFile
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	// Helper function to measure bandwidth of a particular operation
	/*measureBandwidth := func(probe func()) (bandwidth int) {
		before := userlib.DatastoreGetBandwidth()
		probe()
		after := userlib.DatastoreGetBandwidth()
		return after - before
	}**/

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			_ = emptyString
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			_ = aliceLaptop
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Andy Test: Testing Revoke Functionality with multiple shared users", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice creating invite for Doris for file %s, and Doris accepting invite under name %s.", aliceFile, dorisFile)

			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that accessers cannot revoke access from file")
			err = bob.RevokeAccess(aliceFile, "doris")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Doris for file %s, and Doris accepting invite under name %s.", aliceFile, dorisFile)

			invite, err = doris.CreateInvitation(dorisFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("doris", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Doris can still load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Ev can still load the file.")
			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Andy Test: Testing Revoke Functionality with multiple appended blocks", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Rushnan's Test: Testing InitUser/GetUser on multiple users.", func() {
			// initialize Alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// initialize Bob
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", bobPassword)
			Expect(err).To(BeNil())

			//get Alice
			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// get Bob
			_ = bob
			userlib.DebugMsg("Getting user Bob.")
			bobLaptop, err = client.GetUser("bob", bobPassword)
			_ = bobLaptop
			Expect(err).To(BeNil())
		})

		Specify("Rushnan Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			// initialize new user charles
			userlib.DebugMsg("Initializing user charles.")
			charlesLaptop, err = client.InitUser("charles", emptyString)
			_ = charlesLaptop
			Expect(err).To(BeNil())

			// get user charles
			userlib.DebugMsg("Getting second instance of Charles - charlesPhone")
			charlesPhone, err = client.GetUser("charles", emptyString)
			_ = charlesPhone
			Expect(err).To(BeNil())

			// initialize bob phone
			userlib.DebugMsg("Getting phone instance of Bob - bobPhone")
			bobPhone, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// bob creates invitation for charlesLaptop
			userlib.DebugMsg("Bob Phone creating invite for charles Laptop.")
			inviteCharles, err := bobPhone.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			// charles accepts invitation from bob
			userlib.DebugMsg("Charles accepting invite from Bob under filename %s.", charlesFile)
			err = charlesLaptop.AcceptInvitation("bob", inviteCharles, charlesFile)
			Expect(err).To(BeNil())

			// charles appends to charlesFile
			userlib.DebugMsg("Charles appending to file %s, content: %s", charlesFile, contentFour)
			err = charlesLaptop.AppendToFile(charlesFile, []byte(contentFour))
			Expect(err).To(BeNil())

			// load file
			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentFour)))

		})

		Specify("Rushnan Test: Init Bob and bob. Should be different users.", func() {
			// initialize user Bob with username bob
			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// initialize user Bob with username bob
			userlib.DebugMsg("Initializing user bob.")
			Bob, err := client.InitUser("Bob", defaultPassword)
			_ = Bob
			Expect(err).To(BeNil())
		})

		// Alice overwrites a file named aliceFile
		Specify("Rushnan Test: Alice overwrites a file named aliceFile.", func() {
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//get Alice phone
			userlib.DebugMsg("Getting user Alice.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// alicePhone attempts to overwrite aliceFile with contentTwo
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentTwo)
			err = alicePhone.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			// aliceLaptop loads aliceFile
			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

		})

		// load a file that contains empty content
		Specify("Rushnan Test: alice loads aliceFile that contains empty content.", func() {
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, emptyString)
			err = aliceLaptop.StoreFile(aliceFile, []byte(emptyString))
			Expect(err).To(BeNil())

			// aliceLaptop loads aliceFile
			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(emptyString)))

		})

		Specify("Rushnan Test: bob overwrites shared aliceFile when he calls storeFile.", func() {
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// initialize Bob phone
			userlib.DebugMsg("Getting phone instance of Bob - bobPhone")
			bobPhone, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// alice creates invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob phone.")
			inviteBob, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			// bob accepts invitation from alice
			userlib.DebugMsg("Bob accepting invite from alice under filename %s.", aliceFile)
			err = bobPhone.AcceptInvitation("alice", inviteBob, aliceFile)
			Expect(err).To(BeNil())

			// bob stores aliceFile. should be overwritten
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentThree)
			err = bobPhone.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			// aliceLaptop loads aliceFile
			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

		})

		// create a file with empty filename
		Specify("Rushnan Test: alice creates a file with empty string.", func() {
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", emptyString, contentOne)
			err = aliceLaptop.StoreFile(emptyString, []byte(contentOne))
			Expect(err).To(BeNil())

			// initialize bobLaptop
			userlib.DebugMsg("Initializing user Bob laptop.")
			bobLaptop, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// alice creates invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob.")
			inviteBob, err := aliceLaptop.CreateInvitation(emptyString, "bob")
			_ = inviteBob
			Expect(err).To(BeNil())

			// bob accepts invitation
			userlib.DebugMsg("Bob accepting invite from alice under filename %s.", aliceFile)
			err = bobLaptop.AcceptInvitation("alice", inviteBob, emptyString)
			Expect(err).To(BeNil())

		})

		// alice and bob both create a filenamed aliceFile. separate namespaces
		Specify("Rushnan Test: alice and bob both create a file called aliceFile.", func() { // checks flags: 12
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// initialize bobLaptop
			userlib.DebugMsg("Initializing user Bob laptop.")
			bobLaptop, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// bobLaptop stores file
			userlib.DebugMsg("bobLaptop storing file %s with content: %s", aliceFile, contentTwo)
			err = bobLaptop.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			// aliceLaptop loads aliceFile
			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			// bobLaptop loads aliceFile
			userlib.DebugMsg("Checking that bobLaptop sees expected file data.")
			data, err = bobLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

		})

		// appendedBlock name = owner file name
		Specify("Rushnan Test: alice creates a file. Bob wants to append ", func() {
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// initialize bobLaptop
			userlib.DebugMsg("Initializing user Bob laptop.")
			bobLaptop, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// alice creates invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob.")
			inviteBob, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			_ = inviteBob
			Expect(err).To(BeNil())

			// bob accepts invitation
			userlib.DebugMsg("Bob accepting invite from alice under filename %s.", aliceFile)
			err = bobLaptop.AcceptInvitation("alice", inviteBob, aliceFile)
			Expect(err).To(BeNil())

			// bob wants to append his aliceFile to alice's aliceFile
			userlib.DebugMsg("Bob appending to file %s, content: %s", aliceFile, contentFour)
			err = bobLaptop.AppendToFile(aliceFile, []byte(contentFour)) // errors here
			Expect(err).To(BeNil())

		})

		// adversary changes invitation struct
		Specify("Rushnan Test: adversary changes invitation struct ", func() {
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// initialize bobLaptop
			userlib.DebugMsg("Initializing user Bob laptop.")
			bobLaptop, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// alice creates invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob.")
			inviteBob, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			_ = inviteBob
			Expect(err).To(BeNil())

			// mallory changes inviteBob
			inviteBob, err = uuid.FromBytes(userlib.RandomBytes(16))
			if err != nil {
				Expect(err).ToNot(BeNil())
			}
			// bob accepts invitation
			userlib.DebugMsg("Bob accepting invite from alice under filename %s.", aliceFile)
			err = bobLaptop.AcceptInvitation("alice", inviteBob, aliceFile)
			Expect(err).To(BeNil())

			// bob wants to append his aliceFile to alice's aliceFile
			userlib.DebugMsg("Bob appending to file %s, content: %s", aliceFile, contentFour)
			err = bobLaptop.AppendToFile(aliceFile, []byte(contentFour)) // errors here
			Expect(err).To(BeNil())

		})

		// adversary messes with a file
		Specify("Rushnan Test: adversary changes file ", func() {
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// mallory changes aliceFile
			aliceFile = "malloryFile.txt"
			if err != nil {
				Expect(err).ToNot(BeNil())
			}

			// alice creates invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob.")
			inviteBob, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			_ = inviteBob
			Expect(err).To(BeNil())

			// bob accepts invitation
			userlib.DebugMsg("Bob accepting invite from alice under filename %s.", aliceFile)
			err = bobLaptop.AcceptInvitation("alice", inviteBob, aliceFile)
			Expect(err).To(BeNil())

			// bob wants to append his aliceFile to alice's aliceFile
			userlib.DebugMsg("Bob appending to file %s, content: %s", aliceFile, contentFour)
			err = bobLaptop.AppendToFile(aliceFile, []byte(contentFour)) // errors here
			Expect(err).To(BeNil())

		})

		// bob is revoked and the  tries to invite someone else
		Specify("Rushnan Test: bob is revoked and the  tries to invite someone else ", func() {
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// alice creates invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob.")
			inviteBob, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			_ = inviteBob
			Expect(err).To(BeNil())

			// bob accepts invitation
			userlib.DebugMsg("Bob accepting invite from alice under filename %s.", aliceFile)
			err = bobLaptop.AcceptInvitation("alice", inviteBob, aliceFile)
			Expect(err).To(BeNil())

			// bob gets revoked
			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = aliceLaptop.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			// initialize charles
			userlib.DebugMsg("Initializing user Charles laptop.")
			charlesLaptop, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			//bob tries to invite charles
			userlib.DebugMsg("bob laptop creating invite for bob.")
			inviteCharles, err := bobLaptop.CreateInvitation(aliceFile, "charles")
			_ = inviteCharles
			Expect(err).To(BeNil()) // should error

		})

		// ANDY TEST
		Specify("Andy Test: test datastore adversary changing everything except users", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", bobPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob storing file %s with content: %s", bobFile, contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of bob - bobLaptop")
			bobLaptop, err = client.GetUser("bob", bobPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", "iamcharles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles storing file %s with content: %s", charlesFile, contentThree)
			err = charles.StoreFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of charles - charlesLaptop")
			charlesLaptop, err = client.GetUser("charles", "iamcharles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", "b2") //error
			err = bob.AcceptInvitation("alice", invite, "b2")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, "b2")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob appending to file %s, content: %s", "b2", contentTwo)
			err = bob.AppendToFile("b2", []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("bobLaptop creating invite for Charles.")
			invite, err = bobLaptop.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Charles accepting invite from Bob under filename %s.", "c2")
			err = charles.AcceptInvitation("bob", invite, "c2")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Bob appending to file %s, content: %s", "c2", contentTwo)
			err = charles.AppendToFile("c2", []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("charlesLaptop creating invite for Alice.")
			invite, err = charlesLaptop.CreateInvitation(charlesFile, "alice")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice accepting invite from Charles under filename %s.", "a2")
			err = alice.AcceptInvitation("charles", invite, "a2")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice appending to file %s, content: %s", "a2", contentTwo)
			err = alice.AppendToFile("a2", []byte(contentTwo))
			Expect(err).To(BeNil())

			datastoreMap := userlib.DatastoreGetMap()

			for uuid, _ := range datastoreMap {
				userlib.DatastoreSet(uuid, userlib.RandomBytes(64))
			}

			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			_, err = alice.LoadFile("a2")
			Expect(err).ToNot(BeNil())

			err = alice.StoreFile("a3", []byte(contentFour))
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

			invite, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
			err = bob.AcceptInvitation("alice", invite, "b2")
			Expect(err).ToNot(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			bob, err = client.InitUser("bob", bobPassword)
			Expect(err).ToNot(BeNil())

			charles, err = client.InitUser("charles", "iamcharles")
			Expect(err).ToNot(BeNil())
		})

		// alice shares aliceFile with Bob, eve shares aliceFile with Bob
		Specify("Rushnan Test: alice shares aliceFile with Bob, eve shares aliceFile with Bob", func() {
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// initialize charles
			userlib.DebugMsg("Initializing user Charles laptop.")
			charlesLaptop, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			// charlesLaptop stores file
			userlib.DebugMsg("charlesLaptop storing file %s with content: %s", aliceFile, contentTwo)
			err = charlesLaptop.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			// alice creates invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob.")
			inviteBob, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			_ = inviteBob
			Expect(err).To(BeNil())

			// bob accepts invitation
			userlib.DebugMsg("Bob accepting invite from alice under filename %s.", bobFile)
			err = bobLaptop.AcceptInvitation("alice", inviteBob, bobFile)
			Expect(err).To(BeNil())

			// charles creates invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob.")
			inviteBob, err = charlesLaptop.CreateInvitation(aliceFile, "bob")
			_ = inviteBob
			Expect(err).To(BeNil())

			// bob accepts invitation
			userlib.DebugMsg("Bob accepting invite from charles under filename %s.", dorisFile)
			err = bobLaptop.AcceptInvitation("charles", inviteBob, dorisFile)
			Expect(err).To(BeNil())

		})

		// alice shares with bob and charles. bob tries to create invitation for charles
		Specify("Rushnan Test: alice shares with bob and charles. bob tries to create invitation for charles", func() {
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// initialize bobLaptop
			userlib.DebugMsg("Initializing user bob laptop.")
			bobLaptop, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// initialize charles
			userlib.DebugMsg("Initializing user Charles laptop.")
			charlesLaptop, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			// alice creates invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob.")
			inviteBob, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			_ = inviteBob
			Expect(err).To(BeNil())

			// bob accepts invitation
			userlib.DebugMsg("Bob accepting invite from alice under filename %s.", bobFile)
			err = bobLaptop.AcceptInvitation("alice", inviteBob, bobFile)
			Expect(err).To(BeNil())

			// alice creates invitation for charles
			userlib.DebugMsg("Alice laptop creating invite for bob.")
			inviteCharles, err := aliceLaptop.CreateInvitation(aliceFile, "charles")
			_ = inviteBob
			Expect(err).To(BeNil())

			// charles accepts invitation
			userlib.DebugMsg("charles accepting invite from alice under filename %s.", dorisFile)
			err = charlesLaptop.AcceptInvitation("charles", inviteCharles, dorisFile)
			Expect(err).To(BeNil())

			// bob tries to invite charles
			userlib.DebugMsg("Bob laptop creating invite for charles.")
			inviteCharles, err = bobLaptop.CreateInvitation(bobFile, "charles")
			_ = inviteBob
			Expect(err).To(BeNil())

			// charles tries to accept invitation
			userlib.DebugMsg("charles accepting invite from bob under filename %s.", dorisFile)
			err = charlesLaptop.AcceptInvitation("charles", inviteCharles, dorisFile)
			Expect(err).To(BeNil())

		})

		// give access to 3 people. Have owner loadfile and see if all changes are reflected

	})

	Describe("Our Tests", func() {
		// have owner invite themselves to a file
		Specify("Rushnan Test: alice creates a file and tries to invite herself.", func() { // checks flags: 14 // disappeared
			// initialize alice
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// aliceLaptop creates invitation for herself
			userlib.DebugMsg("Alice laptop creating invite for Alice.")
			inviteAlice, err := aliceLaptop.CreateInvitation(aliceFile, "alice")
			_ = inviteAlice
			Expect(err).To(BeNil())

		})

		Specify("Rushnan Test: Init two users with the same username.", func() {
			// initialize user Alice with username alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// initialize user Alice2 with username alice
			_ = alice2
			userlib.DebugMsg("Initializing user Alice.")
			alice2, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil()) // should error since users cant have the same username // result : errors

		})

		Specify("Rushnan Test: Init 1st user with 0 password length and 2nd user with empty username.", func() {
			// initialize user Alice with username alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", emptyString) // should pass since len(password) >= 0
			Expect(err).To(BeNil())

			// initialize user Bob with empty username
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("", defaultPassword)
			Expect(err).To(BeNil()) // should error since users cant have empty username // result : errors

		})
		Specify("Rushnan Test: Attempt to get an uninitialized user.", func() {

			//get Alice
			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil()) // should error since Alice was not initialized // errors
		})

		Specify("Rushnan Test: Initialize a user and try to get user using wrong password.", func() {

			// initialize Alice
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// get Alice
			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", emptyString) // should error since wrong password // errors
			Expect(err).To(BeNil())
		})

		Specify("Rushnan Test: Initialize Alice and Bob and have Bob load a file alice stored which he doesnt have access to.", func() {

			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// initialize bob phone
			userlib.DebugMsg("Initializing user Bob phone.")
			bobPhone, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// get user bobLaptop
			userlib.DebugMsg("Getting user bob.")
			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// bob tries to load aliceFile
			userlib.DebugMsg("Bob tries to load aliceFile.")
			data, err := bobLaptop.LoadFile(aliceFile) // should error here since bob doesnt have access to aliceFile // errors
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		// Alice attempts to share aliceFile with bob without creating aliceFile. checks flag 22
		Specify("Rushnan Test: Alice attempts to share aliceFile with Bob without creating it first.", func() {
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// initialize Bob phone
			userlib.DebugMsg("Getting phone instance of Bob - bobPhone")
			bobPhone, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// alice creates invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob phone.")
			inviteBob, err := aliceLaptop.CreateInvitation(aliceFile, "bob") // shouldnt work since aliceFile doesnt exist
			Expect(err).To(BeNil())

			// bob accepts invitation from alice
			userlib.DebugMsg("Bob accepting invite from alice under filename %s.", bobFile)
			err = bobPhone.AcceptInvitation("bob", inviteBob, bobFile)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// bob stores aliceFile. should be overwritten
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentThree)
			err = bobPhone.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			// aliceLaptop loads aliceFile
			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

		})

		// bob tries to accept an invitation from himself that was never created
		Specify("Rushnan Test: bob tries to accept an invitation from himself that was never created.", func() { // checks flags: 10, 16,18
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// initialize Bob phone
			userlib.DebugMsg("Getting phone instance of Bob - bobPhone")
			bobPhone, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// alice creates invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob phone.")
			inviteBob, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			// bob accepts invitation from alice (ACTUALLY: BOB TRIES TO ACCEPT AN INVITATION THAT WAS NEVER CREATED)
			userlib.DebugMsg("Bob accepting invite from alice under filename %s.", aliceFile)
			err = bobPhone.AcceptInvitation("bob", inviteBob, aliceFile) // ERRORS HERE: Figured it out, because sender username should be alice not bob
			Expect(err).To(BeNil())

			// bob stores aliceFile. should be overwritten
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentThree)
			err = bobPhone.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			// aliceLaptop loads aliceFile
			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

		})

		// try appending before storing
		Specify("Rushnan Test: alice tries to append before creating file.", func() {
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// alice tries to append to aliceFile
			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentThree)) // should error
			Expect(err).To(BeNil())

		})

		// adversary tries to change two file locations
		Specify("Rushnan Test: Adversary tries to change .", func() {
			// initialize user Alice with username alice
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// initialize Bob phone
			userlib.DebugMsg("Getting phone instance of Bob - bobPhone")
			bobPhone, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores aliceFile
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// aliceLaptop stores bobFile
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", bobFile, contentTwo)
			err = aliceLaptop.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			// aliceLaptop loads aliceFile
			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			// adversary
			datastoreMap := userlib.DatastoreGetMap()
			var aliceFileContentUUID userlib.UUID
			var aliceFileContentVal []byte
			var bobFileContentUUID userlib.UUID
			var bobFileContentVal []byte

			for uuid, val := range datastoreMap {
				_ = val
				uuidString := uuid.String()
				uuidBytes := []byte(uuidString)
				uuidBytesToHex := hex.EncodeToString(uuidBytes)
				_ = uuidBytesToHex
				_ = uuidString
				uuidHex := hex.EncodeToString(uuid[:])
				//uuidHexToString :=
				// aliceFile FileContentUUID
				if uuidHex == "4529348bffa59387ff01137098df85f1" {

					aliceFileContentUUID = uuid
					aliceFileContentVal = val

				} else if uuidHex == "bf15e8f614ecdedb234f17b2c7114930" {

					bobFileContentUUID = uuid
					bobFileContentVal = val
				}
			}
			// replace aliceFileContent with bobFileContent and vice versa
			// change datastore value of aliceFile
			userlib.DatastoreSet(aliceFileContentUUID, bobFileContentVal)
			userlib.DatastoreSet(bobFileContentUUID, aliceFileContentVal)

			// aliceLaptop tries to load aliceFile
			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil()) // should error since aliceFile has been replaced with bobFile
			Expect(data).To(Equal([]byte(contentOne)))

		})

		// revoke user before giving them invitation
		Specify("Rushnan Test: alice revokes bob before creating invitation.", func() { // checks flag 6
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, emptyString)
			err = aliceLaptop.StoreFile(aliceFile, []byte(emptyString))
			Expect(err).To(BeNil())

			// initialize bobLaptop
			userlib.DebugMsg("Initializing user Bob laptop.")
			bobLaptop, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil()) // should error since bob was never given access

			// aliceLaptop loads aliceFile
			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(emptyString)))

		})
		
		Specify("double accept", func() {
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// initialize Bob phone
			userlib.DebugMsg("Getting phone instance of Bob - bobPhone")
			bobPhone, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// alice creates invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob phone.")
			inviteBob, err := aliceLaptop.CreateInvitation(aliceFile, "bob") // shouldnt work since aliceFile doesnt exist
			Expect(err).To(BeNil())

			// bob stores aliceFile. should be overwritten
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", bobFile, contentThree)
			err = bobPhone.StoreFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())

			// bob accepts invitation from alice
			userlib.DebugMsg("Bob accepting invite from alice under filename %s.", bobFile)
			err = bobPhone.AcceptInvitation("bob", inviteBob, bobFile)
			Expect(err).To(BeNil())
		})
		
		// post grade release check//
		// check if storefile can store files with empty content
		Specify("Rushnan Test: check if storefile can store files with empty content.", func() { // checks flags: 12
			// initialize Alice laptop
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, []byte(""))
			err = aliceLaptop.StoreFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())

			// aliceLaptop loads aliceFile
			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(emptyString)))
		})

		/*Specify("Andy Test: Datastore Adversary.", func() {
			// initialize user Alice with username alice
			userlib.DebugMsg("Initializing user Alice laptop.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// initialize Bob phone
			userlib.DebugMsg("Getting phone instance of Bob - bobPhone")
			bobPhone, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// aliceLaptop stores file
			userlib.DebugMsg("aliceLaptop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// aliceLaptop loads aliceFile
			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			datastoreMap := userlib.DatastoreGetMap()
			for uuid, _ := range datastoreMap {
				userlib.DatastoreSet(uuid, userlib.RandomBytes(64))
			}

			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())

			// aliceLaptop cannot load aliceFile
			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			Expect(data).ToNot(Equal([]byte(contentOne)))

			// alice cannot invitation for bob
			userlib.DebugMsg("Alice laptop creating invite for bob phone.")
			inviteBob, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			// bob cannot invitation from alice
			userlib.DebugMsg("Bob accepting invite from alice under filename %s.", aliceFile)
			err = bobPhone.AcceptInvitation("alice", inviteBob, aliceFile)
			Expect(err).ToNot(BeNil())
		})**/

	})
})
