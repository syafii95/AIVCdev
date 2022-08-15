#! /usr/bin/env python
# coding=utf-8
#================================================================
#   Copyright (C) 2019 * Ltd. All rights reserved.
#
#   Editor      : VIM
#   File name   : train.py
#   Author      : YunYang1994
#   Created date: 2019-07-18 09:18:54
#   Description :
#
#================================================================

import os
import time
import shutil
import numpy as np
import tensorflow as tf
import core.utils as utils
from tqdm import tqdm
from core.dataset import Dataset
from core.yolov3 import YOLOv3, decode, compute_loss
from core.config import cfg


class AITrainer():
    def __init__(self):
        self.trainset = Dataset('train')
        logdir = "./data/log"
        steps_per_epoch = len(self.trainset)
        self.global_steps = tf.Variable(1, trainable=False, dtype=tf.int64)
        self.warmup_steps = cfg.TRAIN.WARMUP_EPOCHS * steps_per_epoch
        self.total_steps = cfg.TRAIN.EPOCHS * steps_per_epoch
        input_size=cfg.TRAIN.INPUT_SIZE[0]

        input_tensor = tf.keras.layers.Input([input_size, input_size, 3])
        conv_tensors = YOLOv3(input_tensor)

        output_tensors = []
        for i, conv_tensor in enumerate(conv_tensors):
            pred_tensor = decode(conv_tensor, i)
            output_tensors.append(conv_tensor)
            output_tensors.append(pred_tensor)

        self.model = tf.keras.self.Model(input_tensor, output_tensors)
        self.optimizer = tf.keras.optimizers.Adam()
        if os.path.exists(logdir): shutil.rmtree(logdir)
        self.writer = tf.summary.create_file_writer(logdir)

    def train_step(self, image_data, target):
        with tf.GradientTape() as tape:
            pred_result = self.model(image_data, training=True)
            giou_loss=conf_loss=prob_loss=0

            # optimizing process
            for i in range(3):
                conv, pred = pred_result[i*2], pred_result[i*2+1]
                loss_items = compute_loss(pred, conv, *target[i], i)
                giou_loss += loss_items[0]
                conf_loss += loss_items[1]
                prob_loss += loss_items[2]

            total_loss = giou_loss + conf_loss + prob_loss
            if not giou_loss:
                a=input("NANNANANANANANANAN")

            gradients = tape.gradient(total_loss, self.model.trainable_variables)
            self.optimizer.apply_gradients(zip(gradients, self.model.trainable_variables))
            tf.print("=> STEP %4d   lr: %.6f   giou_loss: %4.2f   conf_loss: %4.2f   "
                     "prob_loss: %4.2f   total_loss: %4.2f" %(self.global_steps, self.optimizer.lr.numpy(),
                                                              giou_loss, conf_loss,
                                                              prob_loss, total_loss))

            # update learning rate
            self.global_steps.assign_add(1)
            if self.global_steps < self.warmup_steps:
                lr = self.global_steps / self.warmup_steps *cfg.TRAIN.LR_INIT
            else:
                lr = cfg.TRAIN.LR_END + 0.5 * (cfg.TRAIN.LR_INIT - cfg.TRAIN.LR_END) * (
                    (1 + tf.cos((self.global_steps - self.warmup_steps) / (self.total_steps - self.warmup_steps) * np.pi))
                )
            self.optimizer.lr.assign(lr.numpy())

            # writing summary data
            with self.writer.as_default():
                tf.summary.scalar("lr", self.optimizer.lr, step=self.global_steps)
                tf.summary.scalar("loss/total_loss", total_loss, step=self.global_steps)
                tf.summary.scalar("loss/giou_loss", giou_loss, step=self.global_steps)
                tf.summary.scalar("loss/conf_loss", conf_loss, step=self.global_steps)
                tf.summary.scalar("loss/prob_loss", prob_loss, step=self.global_steps)
            self.writer.flush()

    def startTraining(self):
        e=0
        for epoch in range(cfg.TRAIN.EPOCHS):
            for image_data, target in self.trainset:
                self.train_step(image_data, target)
            self.model.save_weights("./yolov3")
            e+=1
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print(e)
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")

