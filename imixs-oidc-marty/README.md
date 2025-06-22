# OpenID Connect Integration of Imixs-Marty

This project provides a integration handler for ...

### User Profile Update

When using the [Imixs-Marty library](https://github.com/imixs/imixs-marty) the module automatically
updates the user profile with the attributes provided by the OpenID provider. The class `UserProfileHandler` is a CDI Observer bean listening to the Marty Profile event (`org.imixs.marty.profile.ProfileEvent`). A project may implement an alternative mechanism to this bean.
