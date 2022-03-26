def classify(features_train, labels_train): 
    from sklearn.neighbors import KNeighborsClassifier

    knn = KNeighborsClassifier(n_neighbors = 35)
    knn.fit(features_train , labels_train)
    return knn