@Auth or= {}

###
  A valid user will have exactly one of the following identification fields: id, username, or email
###
userValidator = Match.Where (user) ->
  check user,
    id: Match.Optional String
    username: Match.Optional String
    email: Match.Optional String

  if _.keys(user).length is not 1
    throw new Match.Error 'User must have exactly one identifier field'

  return true

###
  A password can be either in plain text or hashed
###
passwordValidator = Match.OneOf(String,
  digest: String
  algorithm: String)

###
  Return a MongoDB query selector for finding the given user
###
getUserQuerySelector = (user) ->
  if user.id
    return {'_id': user.id}
  else if user.username
    return {'username': user.username}
  else if user.email
    return {'emails.address': user.email}

  # We shouldn't be here if the user object was properly validated
  throw new Error 'Cannot create selector from invalid user'

###
  Log a user in with their password
###
@Auth.loginWithPassword = (user, password) ->
  if not user or not password
    throw new Meteor.Error 401, 'Unauthorized'

  console.log("API loginWithPassword: user #{user.username}")
  # Validate the login input types
  check user, userValidator
  check password, passwordValidator

  # Retrieve the user from the database
  authenticatingUserSelector = getUserQuerySelector(user)
  authenticatingUser = Meteor.users.findOne(authenticatingUserSelector)

  if not authenticatingUser
    throw new Meteor.Error 401, 'Unauthorized'
  if not authenticatingUser.services?.password
    throw new Meteor.Error 401, 'Unauthorized'

  # Authenticate the user's password
  passwordVerification = Accounts._checkPassword authenticatingUser, password
  if passwordVerification.error
    console.log("API loginWithPassword: #{user.username} passwordVerification failed")
    throw new Meteor.Error 401, 'Unauthorized'

  # !!! TEP: Clear current tokens for this is causing a mess when they do not log out !!!
  userInfo = Meteor.users.findOne
    _id: authenticatingUser._id

  #console.log("API user tokens", userInfo?.services?.resume?.loginTokens)

  if userInfo?.services?.resume?.loginTokens?.length > 5
    console.log("Too Many Tokens for user #{user.username}")
    count = userInfo.services.resume.loginTokens.length
    while count > 5
      Meteor.users.update
        _id: authenticatingUser._id
      , 
        $pop:
          'services.resume.loginTokens': -1
      count--

    #Accounts._clearAllLoginTokens(authenticatingUser._id)
  
  if authenticatingUser.lastApiToken
    console.log("API [Auth.loginWithPassword]: remove user last token for #{authenticatingUser.username}")
    hashedToken = authenticatingUser.lastApiToken
    tokenLocation = 'services.resume.loginTokens.hashedToken'
    index = tokenLocation.lastIndexOf '.'
    tokenPath = tokenLocation.substring 0, index
    tokenFieldName = tokenLocation.substring index + 1
    tokenToRemove = {}
    tokenToRemove[tokenFieldName] = hashedToken
    tokenRemovalQuery = {}
    tokenRemovalQuery[tokenPath] = tokenToRemove
    Meteor.users.update authenticatingUser._id, {$pull: tokenRemovalQuery}

  # Add a new auth token to the user's account
  authToken = Accounts._generateStampedLoginToken()
  hashedToken = Accounts._hashLoginToken authToken.token
  Accounts._insertHashedLoginToken authenticatingUser._id, {hashedToken}

  Meteor.users.update
    _id: authenticatingUser._id
  ,
    $set:
      lastApiToken: hashedToken

  return {authToken: authToken.token, userId: authenticatingUser._id}

