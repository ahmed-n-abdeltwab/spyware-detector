from prep_terrain_data import makeTerrainData
from class_vis import prettyPicture, clfInfo
from ClassifyDT import classify

import numpy as np
import pylab as pl



X_train, X_test, y_train, y_test = makeTerrainData()


# You will need to complete this function imported from the ClassifyNB script.
# Be sure to change to that code tab to complete this quiz.
clf = classify(X_train, y_train)



### draw the decision boundary with the text points overlaid
clfInfo(clf, X_test, y_test)