# importing the necessary libraries
import cv2
import numpy as np
 
# Creating a VideoCapture object to read the video
cap = cv2.VideoCapture('rust3.mp4')
 
 
# Loop until the end of the video
while (cap.isOpened()):
 
    # Capture frame-by-frame
    ret, frame = cap.read()
    frame = cv2.resize(frame, (540, 380), fx = 0, fy = 0,
                         interpolation = cv2.INTER_CUBIC)
 
    # Display the resulting frame
    cv2.imshow('Original', frame)
 
    # conversion of BGR to grayscale is necessary to apply this operation
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    img_hsv=cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
    imgray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

    ret, thresh = cv2.threshold(imgray, 127, 255, 0)
    contours, heirarachy = cv2.findContours(thresh, cv2.RETR_TREE, cv2.CHAIN_APPROX_NONE)

    #cv2.drawContours(frame,contours, -1, (0,255,0), 3)

    # Range for lower red
    lower_red = np.array([0,100,100])
    upper_red = np.array([20,200,150])
    mask0 = cv2.inRange(img_hsv, lower_red, upper_red)
    
    # range for upper red
    lower_red = np.array([170,70,70])
    upper_red = np.array([180,200,150])
    mask1 = cv2.inRange(img_hsv, lower_red, upper_red)
    
    # add both masks
    mask = mask0+mask1
    
    output_img = cv2.bitwise_and(frame,frame,mask=mask)
    
    scale_percent = 60 # percent of original size
    width = int(output_img.shape[1] * scale_percent / 100)
    height = int(output_img.shape[0] * scale_percent / 100)
    dim = (width, height)

    resized = cv2.resize(output_img, dim, interpolation = cv2.INTER_AREA)
    # adaptive thresholding to use different threshold
    # values on different regions of the frame.
    #Thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_MEAN_C,cv2.THRESH_BINARY_INV, 11, 2)
 
    cv2.imshow('Detection', output_img)
    #cv2.imshow('Contour', frame)
    #cv2.imshow('HSV',img_hsv)
    # define q as the exit button
    if cv2.waitKey(25) & 0xFF == ord('q'):
        break
 
# release the video capture object
cap.release()
# Closes all the windows currently opened.
cv2.destroyAllWindows()