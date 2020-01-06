//
// Created by slahmer on 11/9/19.
//

#ifndef NET_TRAFFIC_ANALYSER_GLOBAL_H
#define NET_TRAFFIC_ANALYSER_GLOBAL_H

/**
 * @var verbose: this is global variable that defines the level of informations to display
 * @remarks :
 *              verbose = 1 ==> is the default value, in this mode two lines will be displayed
 *              verbose = 2 ==> in this mode each layer, will be displayed briefly
 *              verbose = 3 ==> in this mode all layers informations will be dumped
 *
 *              if value entered is greater than 3 then the mode will be considered as 3
 *              if value entered is lower than 1 then the mode will be considered as 1
 */
extern int verbose;

#endif //NET_TRAFFIC_ANALYSER_GLOBAL_H
