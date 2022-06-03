def classify(features_train, labels_train):   
    ### import the sklearn module for GaussianNB
    ### create classifier
    ### fit the classifier on the training features and labels
    ### return the fit classifier

    
    ### your code goes here!
    
    from sklearn.linear_model import LogisticRegression
    reg = 0.01
    clf = LogisticRegression(C=reg, solver="liblinear").fit(features_train, labels_train)
    return clf